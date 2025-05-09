package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/hooks/hookafter"
	"github.com/supabase/auth/internal/hooks/v1hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

func (a *API) afterhooksMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(hookafter.With(r.Context()))
		defer func() {
			if err := hookafter.Fire(r.Context()); err != nil {
				log := observability.GetLogEntry(r).Entry
				log.WithError(err).Warn("error triggering 1 or more hooks")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *API) triggerBeforeUserCreated(
	r *http.Request,
	conn *storage.Connection,
	user *models.User,
) error {
	if !a.hooksMgr.Enabled(v1hooks.BeforeUserCreated) {
		return nil
	}

	req := v1hooks.NewBeforeUserCreatedRequest(r, user)
	res := new(v1hooks.BeforeUserCreatedResponse)
	return a.hooksMgr.BeforeUserCreated(r.Context(), conn, req, res)
}

func (a *API) triggerAfterUserCreated(
	r *http.Request,
	userID uuid.UUID,
) error {
	if !a.hooksMgr.Enabled(v1hooks.AfterUserCreated) {
		return nil
	}

	return hookafter.Queue(r.Context(), v1hooks.AfterUserCreated, func() error {
		db := a.db.WithContext(r.Context())

		// We reload the user so if some kind of rollback occurs later in
		// the request we don't send an after-user-created event with no
		// associated user. This also guarantees we fetch the user as
		// it would be seen in future requests.
		user, err := models.FindUserByID(db, userID)
		if err != nil {
			return err
		}

		req := v1hooks.NewAfterUserCreatedRequest(r, user)
		res := new(v1hooks.AfterUserCreatedResponse)
		return a.hooksMgr.AfterUserCreated(r.Context(), db, req, res)
	})
}
