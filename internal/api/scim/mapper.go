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

	meta := core.NewMeta(m.baseURL, core.ResourceTypeUser, core.EndpointUsers, id)
	meta.Created, meta.LastModified = u.CreatedAt.UTC(), u.UpdatedAt.UTC()

	user := &core.User{
		Schemas:  []core.SchemaURI{core.SchemaUser},
		ID:       id,
		UserName: email,
		Meta:     meta,
	}

	if email != "" {
		user.Emails = []core.Email{{Value: email, Primary: true}}
	}

	return user
}
