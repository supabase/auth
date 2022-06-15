package api

import (
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"net/http"
)

func (a *API) EnableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if user.MFAEnabled {
		return MFANotEnabled
	}
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.EnableMFA(tx); terr != nil {
			return terr
		}

		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserModifiedAction, r.RemoteAddr, map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, user)

}

func (a *API) DisableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if !user.MFAEnabled {
		return MFANotDisabled
	}
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.DisableMFA(tx); terr != nil {
			return terr
		}

		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserModifiedAction, r.RemoteAddr, map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return terr
		}

		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, user)

}
