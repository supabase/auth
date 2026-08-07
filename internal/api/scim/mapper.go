package scim

import (
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/models"
)

type Mapper[TIn, TOut any] interface {
	MapFrom(in TIn) TOut
}

type UserMapper struct {
	baseURL string
}

func NewUserMapper(baseURL string) UserMapper {
	return UserMapper{baseURL: baseURL}
}

func (m UserMapper) MapFrom(in models.ProvisionedUser) *core.User {
	id := in.ID.String()

	meta := core.NewMeta(m.baseURL, core.ResourceTypeUser, core.EndpointUsers, id)
	meta.Created, meta.LastModified = in.CreatedAt.UTC(), in.UpdatedAt.UTC()

	user := &core.User{
		Schemas:  []core.SchemaURI{core.SchemaUser},
		ID:       id,
		UserName: userName(in),
		Name:     name(in),
		Meta:     meta,
	}

	if address := email(in); address != "" {
		user.Emails = []core.Email{{Value: address, Primary: true}}
	}

	return user
}

func email(in models.ProvisionedUser) string {
	if email := in.Claim("email"); email != "" {
		return email
	}
	return in.GetEmail()
}

func userName(in models.ProvisionedUser) string {
	if userName := in.Claim("preferred_username"); userName != "" {
		return userName
	}
	return email(in)
}

func name(in models.ProvisionedUser) *core.Name {
	name := core.Name{
		Formatted:  in.Claim("name"),
		FamilyName: in.Claim("family_name"),
		GivenName:  in.Claim("given_name"),
		MiddleName: in.Claim("middle_name"),
	}

	if name.IsZero() {
		return nil
	}
	return &name
}
