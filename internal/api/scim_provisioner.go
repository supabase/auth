package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/api/scim"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const scimBanDuration = 100 * 365 * 24 * time.Hour

type scimProvisioner struct {
	api *API
}

func newSCIMProvisioner(api *API) scim.Provisioner {
	return &scimProvisioner{api: api}
}

func (p *scimProvisioner) CreateUser(ctx context.Context, providerID uuid.UUID, input scim.UserInput) (*models.SCIMUser, error) {
	if input.Email == "" {
		return nil, scimerrors.ErrInvalidValue(`"emails" is required`)
	}

	r, err := p.request(ctx)
	if err != nil {
		return nil, err
	}
	db := p.api.db.WithContext(ctx)
	providerType := "sso:" + providerID.String()

	if p.api.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		decision, err := p.decide(db, providerType, input)
		if err != nil {
			return nil, err
		}
		if decision.Decision == models.CreateAccount {
			user, err := p.newUser(providerType, decision, input)
			if err != nil {
				return nil, err
			}
			if err := p.api.triggerBeforeUserCreated(r, db, user); err != nil {
				return nil, hookError(err)
			}
		}
	}

	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if row, terr = models.CreateSCIMUser(tx, providerID, input.Resource); terr != nil {
			return terr
		}

		decision, terr := p.decide(tx, providerType, input)
		if terr != nil {
			return terr
		}

		var user *models.User
		switch decision.Decision {
		case models.AccountExists:
			user = decision.User
		case models.LinkAccount:
			user = decision.User
			if _, terr = p.api.createNewIdentity(tx, user, providerType, identityData(input)); terr != nil {
				return terr
			}
			if terr = user.UpdateAppMetaDataProviders(tx); terr != nil {
				return terr
			}
		case models.CreateAccount:
			if user, terr = p.newUser(providerType, decision, input); terr != nil {
				return terr
			}
			if user, terr = p.api.signupNewUser(tx, user); terr != nil {
				return terr
			}
			if _, terr = p.api.createNewIdentity(tx, user, providerType, identityData(input)); terr != nil {
				return terr
			}
			created = user
		case models.MultipleAccounts:
			return scimerrors.ErrUniqueness("multiple users share this email in the SSO provider")
		default:
			return apierrors.NewInternalServerError("Unknown automatic linking decision: %v", decision.Decision)
		}

		if terr = models.LinkSCIMUser(tx, row, user.ID); terr != nil {
			return terr
		}
		if input.Active {
			return nil
		}
		if terr = user.Ban(tx, scimBanDuration); terr != nil {
			return terr
		}
		return models.Logout(tx, user.ID)
	})
	if err != nil {
		return nil, err
	}

	if created != nil {
		if err := p.api.triggerAfterUserCreated(r, db, created); err != nil {
			logrus.WithError(err).WithField("user_id", created.ID).Error("scim: after user created hook failed")
		}
	}
	return row, nil
}

func (p *scimProvisioner) ReplaceUser(ctx context.Context, providerID, id uuid.UUID, input scim.UserInput, updatedAt *time.Time) (*models.SCIMUser, error) {
	var row *models.SCIMUser
	err := p.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		var terr error
		row, terr = models.ReplaceSCIMUser(tx, providerID, id, input.Resource, updatedAt)
		return terr
	})
	return row, err
}

func (p *scimProvisioner) DeleteUser(ctx context.Context, providerID, id uuid.UUID) error {
	return p.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		return models.DeleteSCIMUser(tx, providerID, id)
	})
}

func (p *scimProvisioner) request(ctx context.Context) (*http.Request, error) {
	r := scimRequestKey.Value(ctx)
	if r == nil {
		return nil, apierrors.NewInternalServerError("SCIM request missing from context")
	}
	return r.WithContext(ctx), nil
}

func (p *scimProvisioner) decide(conn *storage.Connection, providerType string, input scim.UserInput) (models.AccountLinkingResult, error) {
	emails := []provider.Email{{Email: input.Email, Verified: true, Primary: true}}
	return models.DetermineAccountLinking(conn, p.api.config, emails, p.api.config.JWT.Aud, providerType, input.UserName)
}

func (p *scimProvisioner) newUser(providerType string, decision models.AccountLinkingResult, input scim.UserInput) (*models.User, error) {
	params := &SignupParams{
		Provider: providerType,
		Email:    decision.CandidateEmail.Email,
		Aud:      p.api.config.JWT.Aud,
		Data:     identityData(input),
	}
	user, err := params.ToUserModel(true)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	user.EmailConfirmedAt = &now
	return user, nil
}

func identityData(input scim.UserInput) map[string]any {
	return map[string]any{
		"sub":            input.UserName,
		"email":          input.Email,
		"email_verified": true,
	}
}

func hookError(err error) error {
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) && httpErr.HTTPStatus < http.StatusInternalServerError {
		return scimerrors.NewError(httpErr.HTTPStatus, "", httpErr.Message)
	}
	return err
}
