package api

import (
	"context"
	"encoding/json"
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

type scimProvisioner struct {
	api *API
}

func newSCIMProvisioner(api *API) scim.Provisioner {
	return &scimProvisioner{api: api}
}

func (p *scimProvisioner) CreateUser(ctx context.Context, providerID uuid.UUID, input scim.UserInput) (*models.SCIMUser, error) {
	if input.Email == "" {
		return nil, errEmailRequired()
	}
	r, err := p.request(ctx)
	if err != nil {
		return nil, err
	}
	db := p.api.db.WithContext(ctx)
	if err := p.beforeCreate(r, db, providerID, input); err != nil {
		return nil, err
	}

	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.LockAccountLinking(tx, "sso:"+providerID.String(), input.Email); terr != nil {
			return terr
		}
		var terr error
		if row, terr = models.CreateSCIMUser(tx, providerID, input.Resource); terr != nil {
			return terr
		}
		user, isNew, terr := p.link(tx, row, input)
		if terr != nil {
			return terr
		}
		if isNew {
			created = user
		}
		if !input.Active {
			return deactivate(tx, user)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p.afterCreate(r, db, created)
	return row, nil
}

func (p *scimProvisioner) ReplaceUser(ctx context.Context, providerID, id uuid.UUID, input scim.UserInput, updatedAt *time.Time) (*models.SCIMUser, error) {
	r, err := p.request(ctx)
	if err != nil {
		return nil, err
	}
	db := p.api.db.WithContext(ctx)
	existing, err := models.FindSCIMUser(db, providerID, id)
	if err != nil {
		return nil, err
	}
	if existing.UserID == nil {
		if input.Email == "" {
			return nil, errEmailRequired()
		}
		if err := p.beforeCreate(r, db, providerID, input); err != nil {
			return nil, err
		}
	}

	var row *models.SCIMUser
	var created *models.User
	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.LockAccountLinking(tx, "sso:"+providerID.String(), input.Email); terr != nil {
			return terr
		}
		old, terr := models.FindSCIMUserForUpdate(tx, providerID, id)
		if terr != nil {
			return terr
		}
		if row, terr = models.ReplaceSCIMUser(tx, providerID, id, input.Resource, updatedAt); terr != nil {
			return terr
		}

		if old.UserID == nil {
			if input.Email == "" {
				return errEmailRequired()
			}
			user, isNew, terr := p.link(tx, row, input)
			if terr != nil {
				return terr
			}
			if isNew {
				created = user
			}
			if !row.Active {
				return deactivate(tx, user)
			}
			return nil
		}

		user, terr := models.FindUserByID(tx, *old.UserID)
		if terr != nil {
			return terr
		}
		if from := userName(old.Resource); from != input.UserName {
			data := map[string]any{"sub": input.UserName}
			if input.Email != "" {
				data["email"] = input.Email
			}
			if terr := models.RenameSCIMIdentity(tx, user.ID, "sso:"+providerID.String(), from, input.UserName, data); terr != nil {
				return terr
			}
		}
		if old.Active && !row.Active {
			return deactivate(tx, user)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	p.afterCreate(r, db, created)
	return row, nil
}

func (p *scimProvisioner) DeleteUser(ctx context.Context, providerID, id uuid.UUID, updatedAt *time.Time) error {
	return p.api.db.WithContext(ctx).Transaction(func(tx *storage.Connection) error {
		row, err := models.DeleteSCIMUser(tx, providerID, id, updatedAt)
		if err != nil || row.UserID == nil {
			return err
		}
		user, err := models.FindUserByID(tx, *row.UserID)
		if err != nil {
			return err
		}
		return deactivate(tx, user)
	})
}

func (p *scimProvisioner) link(tx *storage.Connection, row *models.SCIMUser, input scim.UserInput) (*models.User, bool, error) {
	providerType := "sso:" + row.SSOProviderID.String()
	decision, err := p.decide(tx, providerType, input)
	if err != nil {
		return nil, false, err
	}

	user := decision.User
	switch decision.Decision {
	case models.AccountExists:
	case models.LinkAccount:
		if _, err = p.api.createNewIdentity(tx, user, providerType, identityData(input)); err != nil {
			return nil, false, err
		}
		if err = user.UpdateAppMetaDataProviders(tx); err != nil {
			return nil, false, err
		}
	case models.CreateAccount:
		if user, err = p.newUser(providerType, decision, input); err != nil {
			return nil, false, err
		}
		if user, err = p.api.signupNewUser(tx, user); err != nil {
			return nil, false, err
		}
		if _, err = p.api.createNewIdentity(tx, user, providerType, identityData(input)); err != nil {
			return nil, false, err
		}
		return user, true, models.LinkSCIMUser(tx, row, user.ID)
	case models.MultipleAccounts:
		return nil, false, scimerrors.ErrUniqueness("multiple users share this email in the SSO provider")
	default:
		return nil, false, apierrors.NewInternalServerError("Unknown automatic linking decision: %v", decision.Decision)
	}

	return user, false, models.LinkSCIMUser(tx, row, user.ID)
}

func (p *scimProvisioner) beforeCreate(r *http.Request, db *storage.Connection, providerID uuid.UUID, input scim.UserInput) error {
	if !p.api.hooksMgr.Enabled(v0hooks.BeforeUserCreated) {
		return nil
	}
	providerType := "sso:" + providerID.String()
	decision, err := p.decide(db, providerType, input)
	if err != nil || decision.Decision != models.CreateAccount {
		return err
	}
	user, err := p.newUser(providerType, decision, input)
	if err != nil {
		return err
	}
	return hookError(p.api.triggerBeforeUserCreated(r, db, user))
}

func (p *scimProvisioner) afterCreate(r *http.Request, db *storage.Connection, user *models.User) {
	if user == nil {
		return
	}
	if err := p.api.triggerAfterUserCreated(r, db, user); err != nil {
		logrus.WithError(err).WithField("user_id", user.ID).Error("scim: after user created hook failed")
	}
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

func deactivate(tx *storage.Connection, user *models.User) error {
	return models.Logout(tx, user.ID)
}

func errEmailRequired() error {
	return scimerrors.ErrInvalidValue(`"emails" is required`)
}

func identityData(input scim.UserInput) map[string]any {
	return map[string]any{
		"sub":            input.UserName,
		"email":          input.Email,
		"email_verified": true,
	}
}

func userName(resource []byte) string {
	var r struct {
		UserName string `json:"userName"`
	}
	_ = json.Unmarshal(resource, &r)
	return r.UserName
}

func hookError(err error) error {
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) && httpErr.HTTPStatus < http.StatusInternalServerError {
		return scimerrors.NewError(httpErr.HTTPStatus, "", httpErr.Message)
	}
	return err
}
