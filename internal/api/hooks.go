package api

import (
	"net/http"
	"strings"

	"github.com/fatih/structs"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func (a *API) triggerBeforeUserCreated(
	r *http.Request,
	db *storage.Connection,
	user *models.User,
) error {
	if !a.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	if err := checkTX(db); err != nil {
		return err
	}

	req := v0hooks.NewBeforeUserCreatedInput(r, user)
	res := new(v0hooks.BeforeUserCreatedOutput)
	return a.hooksMgr.InvokeHook(db, r, req, res)
}

func (a *API) triggerBeforeUserCreatedExternal(
	r *http.Request,
	db *storage.Connection,
	userData *provider.UserProvidedData,
	providerType string,
) error {
	if !a.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	if err := checkTX(db); err != nil {
		return err
	}

	ctx := r.Context()
	aud := a.requestAud(ctx, r)
	config := a.config

	var identityData map[string]interface{}
	if userData.Metadata != nil {
		identityData = structs.Map(userData.Metadata)
	}

	var (
		err      error
		decision models.AccountLinkingResult
	)
	err = db.Transaction(func(tx *storage.Connection) error {
		decision, err = models.DetermineAccountLinking(
			tx, config, userData.Emails, aud,
			providerType, userData.Metadata.Subject)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	if decision.Decision != models.CreateAccount {
		return nil
	}
	if config.DisableSignup {
		return apierrors.NewUnprocessableEntityError(
			apierrors.ErrorCodeSignupDisabled,
			"Signups not allowed for this instance")
	}

	params := &SignupParams{
		Provider: providerType,
		Email:    decision.CandidateEmail.Email,
		Aud:      aud,
		Data:     identityData,
	}

	isSSOUser := false
	if strings.HasPrefix(decision.LinkingDomain, "sso:") {
		isSSOUser = true
	}

	user, err := params.ToUserModel(isSSOUser)
	if err != nil {
		return err
	}
	return a.triggerBeforeUserCreated(r, db, user)
}

func checkTX(conn *storage.Connection) error {
	if conn.TX != nil {
		return apierrors.NewInternalServerError(
			"unable to trigger hooks during transaction")
	}
	return nil
}
