package models

import (
	"time"

	"github.com/supabase/auth/internal/api/scim/core"
)

type ProvisionedUser struct {
	*User
	Identity *Identity
}

func (u *ProvisionedUser) PrimaryEmail() string {
	if email := u.Claim("email"); email != "" {
		return email
	}
	return u.GetEmail()
}

func (u *ProvisionedUser) UserName() string {
	if userName := u.Claim("preferred_username"); userName != "" {
		return userName
	}
	return u.PrimaryEmail()
}

func (u *ProvisionedUser) Claim(key string) string {
	if u.Identity == nil {
		return ""
	}
	value, _ := u.Identity.IdentityData[key].(string)
	return value
}

func (u *ProvisionedUser) ResourceID() string {
	return u.ID.String()
}

func (u *ProvisionedUser) ResourceType() core.ResourceType {
	return core.ResourceTypeUser
}

func (u *ProvisionedUser) Timestamps() (created, updated time.Time) {
	return u.CreatedAt, u.UpdatedAt
}
