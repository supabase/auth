package api

import (
	"net/http"

	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (a *API) triggerBeforeUserCreated(
	r *http.Request,
	conn *storage.Connection,
	user *models.User,
) error {
	if !a.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}

	req := v0hooks.NewBeforeUserCreatedInput(r, user)
	res := new(v0hooks.BeforeUserCreatedOutput)
	return a.hooksMgr.InvokeHook(conn, r, req, res)
}
