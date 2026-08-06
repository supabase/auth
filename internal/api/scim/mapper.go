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

func (m UserMapper) MapFrom(u *models.User) *core.User {
	id, email := u.ID.String(), u.GetEmail()

	user := core.
		NewUser(m.baseURL, id, email, !u.IsBanned()).
		At(u.CreatedAt.UTC(), u.UpdatedAt.UTC())

	if name := nameFrom(u.UserMetaData); name != nil {
		user.Named(*name)
	}

	if email != "" {
		user.WithEmails(core.Email{Value: email, Primary: true})
	}

	return user
}

func nameFrom(metaData models.JSONMap) *core.Name {
	name := core.Name{
		Formatted:  firstString(metaData, "full_name", "name"),
		FamilyName: firstString(metaData, "family_name", "last_name"),
		GivenName:  firstString(metaData, "given_name", "first_name"),
	}

	if name == (core.Name{}) {
		return nil
	}

	return &name
}

func firstString(metaData models.JSONMap, keys ...string) string {
	for _, key := range keys {
		if value, ok := metaData[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
