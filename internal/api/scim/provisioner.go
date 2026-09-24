package scim

import (
	"context"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/models"
)

type UserInput struct {
	Resource []byte
	UserName string
	Email    string
	Active   bool
}

type Provisioner interface {
	CreateUser(ctx context.Context, providerID uuid.UUID, user UserInput) (*models.SCIMUser, error)
	ReplaceUser(ctx context.Context, providerID, id uuid.UUID, user UserInput, updatedAt *time.Time) (*models.SCIMUser, error)
	DeleteUser(ctx context.Context, providerID, id uuid.UUID) error
}

func toInput(user *core.User) (UserInput, error) {
	resource, err := toResource(user)
	if err != nil {
		return UserInput{}, err
	}
	return UserInput{
		Resource: resource,
		UserName: user.UserName,
		Email:    primaryEmail(user.Emails),
		Active:   user.Active == nil || *user.Active,
	}, nil
}

func primaryEmail(emails []core.Email) string {
	for _, email := range emails {
		if email.Primary != nil && *email.Primary {
			return email.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}
