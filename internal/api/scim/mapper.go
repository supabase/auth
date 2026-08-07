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

func (m UserMapper) MapFrom(in *models.ProvisionedUser) *core.User {
	id := in.ID.String()

	return &core.User{
		Schemas:  []core.SchemaURI{core.SchemaUser},
		ID:       id,
		UserName: in.UserName(),
		Name: core.Name{
			Formatted:  in.Claim("name"),
			FamilyName: in.Claim("family_name"),
			GivenName:  in.Claim("given_name"),
			MiddleName: in.Claim("middle_name"),
		},
		Emails: []core.Email{{Value: in.PrimaryEmail(), Primary: true}},
		Meta:   core.NewMeta(m.baseURL, core.ResourceTypeUser, core.EndpointUsers, id).At(in.CreatedAt, in.UpdatedAt),
	}
}
