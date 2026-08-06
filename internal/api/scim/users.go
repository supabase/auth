package scim

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/api/shared"
	"github.com/supabase/auth/internal/models"
)

func (srv *Server) UserByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	id, err := uuid.FromString(chi.URLParam(r, "id"))
	if err != nil {
		return userNotFound(w)
	}

	provider := shared.GetSSOProvider(ctx)
	user, err := models.FindUserByIDAndSSOProviderID(srv.db.WithContext(ctx), id, provider.ID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return userNotFound(w)
		}
		return srv.internalError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, srv.users.MapFrom(user))
}

func userNotFound(w http.ResponseWriter) error {
	return protocol.SendError(w, http.StatusNotFound, "", "Resource not found")
}
