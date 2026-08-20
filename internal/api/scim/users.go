package scim

import (
	"errors"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/api/shared"
)

func (srv *Server) UserByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	id, err := uuid.FromString(urlParam(r, "id"))
	if err != nil {
		return srv.NotFound(w, r)
	}

	provider := shared.GetSSOProvider(ctx)
	if provider == nil {
		return srv.NotFound(w, r)
	}

	user, err := srv.users.Get(ctx, provider.ID.String(), id.String())
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return srv.NotFound(w, r)
		}
		return srv.internalError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, user)
}

func (srv *Server) Users(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	if rejected, err := rejectFilter(w, r, http.StatusBadRequest, protocol.ScimTypeInvalidFilter); rejected {
		return err
	}

	page, err := protocol.ParsePage(r.URL.Query())
	if err != nil {
		return protocol.SendError(w, http.StatusBadRequest, protocol.ScimTypeInvalidValue, err.Error())
	}

	provider := shared.GetSSOProvider(ctx)
	if provider == nil {
		return srv.NotFound(w, r)
	}

	users, total, err := srv.users.List(ctx, provider.ID.String(), page.Count, page.Offset())
	if err != nil {
		return srv.internalError(w, r, err)
	}

	return protocol.Send(w, http.StatusOK, protocol.NewPage(users, page.StartIndex, total))
}

func newUserSchema(baseURL string) *core.Schema {
	return core.
		NewSchema(baseURL, core.KindUser).
		Describe("User Account").
		With(
			core.NewAttribute("userName", core.TypeString, "Unique identifier for the User.").
				AsRequired().
				UniqueOn(core.UniquenessServer),
		)
}
