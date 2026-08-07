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
	return &core.User{
		Schemas:  []core.SchemaURI{core.SchemaUser},
		ID:       in.ResourceID(),
		UserName: in.UserName(),
		Name: core.Name{
			Formatted:  in.Claim("name"),
			FamilyName: in.Claim("family_name"),
			GivenName:  in.Claim("given_name"),
			MiddleName: in.Claim("middle_name"),
		},
		Emails: []core.Email{{Value: in.PrimaryEmail(), Primary: true}},
		Meta:   in.ResourceType().Meta(m.baseURL).For(in),
	}
}
