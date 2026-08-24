package scim

import (
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/storage"
)

type Store[T any] interface {
	For(tenant string) Repository[T]
}

type UserStore struct {
	db          *storage.Connection
	externalURL string
}

func NewUserStore(db *storage.Connection, externalURL string) Store[*core.User] {
	return &UserStore{db: db, externalURL: externalURL}
}

func (s *UserStore) For(tenant string) Repository[*core.User] {
	return &userRepository{
		db:       s.db,
		usersURL: core.KindUser.Location(core.Join(s.externalURL, BasePath)),
		tenant:   tenant,
	}
}
