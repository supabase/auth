package api

import (
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

func (s *scimUserRepository) provisionAuthUser(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, error) {
	linked, isNew, err := s.linkAuthUser(tx, row, user)
	if err != nil {
		return nil, err
	}
	var created *models.User
	if isNew {
		created = linked
	}
	if !row.Active {
		return created, models.LogoutUserForSCIM(tx, linked.ID)
	}
	return created, nil
}

func (s *scimUserRepository) linkAuthUser(tx *storage.Connection, row *models.SCIMUser, user *core.User) (*models.User, bool, error) {
	providerType := scimProviderType(row.SSOProviderID)
	decision, err := s.decideAccountLinking(tx, providerType, user)
	if err != nil {
		return nil, false, err
	}

	if decision.Decision == models.CreateAccount {
		linked, err := s.createAuthUser(tx, providerType, decision, user)
		if err != nil {
			return nil, false, err
		}
		return linked, true, models.LinkNewSCIMUser(tx, row, linked.ID)
	}
	linked, err := s.existingAuthUser(tx, providerType, decision, user)
	if err != nil {
		return nil, false, err
	}
	return linked, false, models.LinkSCIMUser(tx, row, linked.ID)
}

func (s *scimUserRepository) existingAuthUser(tx *storage.Connection, providerType string, decision models.AccountLinkingResult, user *core.User) (*models.User, error) {
	switch decision.Decision {
	case models.AccountExists, models.LinkAccount:
		if err := scimRequireSSOUser(decision.User); err != nil {
			return nil, err
		}
		if decision.Decision == models.LinkAccount {
			if err := s.linkIdentity(tx, decision.User, providerType, user); err != nil {
				return nil, err
			}
		}
		return decision.User, nil
	case models.MultipleAccounts:
		return nil, scimerrors.ErrUniqueness("multiple users share this email in the SSO provider")
	}
	return nil, apierrors.NewInternalServerError("Unknown automatic linking decision: %v", decision.Decision)
}

func (s *scimUserRepository) linkIdentity(tx *storage.Connection, linked *models.User, providerType string, user *core.User) error {
	if _, err := s.api.createNewIdentity(tx, linked, providerType, scimIdentityData(user)); err != nil {
		return err
	}
	return linked.UpdateAppMetaDataProviders(tx)
}

func scimRequireSSOUser(linked *models.User) error {
	if !linked.IsSSOUser {
		return scimerrors.ErrUniqueness("user is not an SSO user")
	}
	return nil
}

func (s *scimUserRepository) createAuthUser(tx *storage.Connection, providerType string, decision models.AccountLinkingResult, user *core.User) (*models.User, error) {
	candidate, err := s.newUser(providerType, decision, user)
	if err != nil {
		return nil, err
	}
	created, err := s.api.signupNewUser(tx, candidate)
	if err != nil {
		return nil, err
	}
	if _, err := s.api.createNewIdentity(tx, created, providerType, scimIdentityData(user)); err != nil {
		return nil, err
	}
	return created, nil
}

func (s *scimUserRepository) beforeProvision(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if scimUserEmail(user) == "" {
		return errSCIMEmailRequired()
	}
	return scimError(s.runBeforeUserCreatedHook(r, db, providerID, user))
}

func (s *scimUserRepository) runBeforeUserCreatedHook(r *http.Request, db *storage.Connection, providerID uuid.UUID, user *core.User) error {
	if !s.api.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	providerType := scimProviderType(providerID)
	decision, err := s.decideAccountLinking(db, providerType, user)
	if err != nil || decision.Decision != models.CreateAccount {
		return err
	}
	candidate, err := s.newUser(providerType, decision, user)
	if err != nil {
		return err
	}
	return scimHookError(s.api.triggerBeforeUserCreated(r, db, candidate))
}

func (s *scimUserRepository) runAfterUserCreatedHook(r *http.Request, db *storage.Connection, user *models.User) {
	if user == nil {
		return
	}
	if err := s.api.triggerAfterUserCreated(r, db, user); err != nil {
		observability.GetLogEntry(r).Entry.WithError(err).WithField("user_id", user.ID).Error("scim: after user created hook failed")
	}
}

func (s *scimUserRepository) decideAccountLinking(conn *storage.Connection, providerType string, user *core.User) (models.AccountLinkingResult, error) {
	emails := []provider.Email{{Email: scimUserEmail(user), Verified: true, Primary: true}}
	return models.DetermineAccountLinking(conn, s.api.config, emails, s.api.config.JWT.Aud, providerType, user.UserName)
}

func (s *scimUserRepository) newUser(providerType string, decision models.AccountLinkingResult, user *core.User) (*models.User, error) {
	params := &SignupParams{
		Provider: providerType,
		Email:    decision.CandidateEmail.Email,
		Aud:      s.api.config.JWT.Aud,
		Data:     scimIdentityData(user),
	}
	candidate, err := params.ToUserModel(true)
	if err != nil {
		return nil, err
	}
	now := s.api.Now()
	candidate.EmailConfirmedAt = &now
	return candidate, nil
}
