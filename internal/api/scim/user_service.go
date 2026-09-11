package scim

import (
	"context"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

type userService struct {
	repo Repository[*core.User]
}

func NewUserService(repo Repository[*core.User]) Service[*core.User] {
	return &userService{repo: repo}
}

func (s *userService) Get(ctx context.Context, id string) (*core.User, error) {
	return s.repo.Get(ctx, id)
}

func (s *userService) List(ctx context.Context, query *protocol.SearchRequest) ([]*core.User, int, error) {
	return s.repo.List(ctx, query)
}

func (s *userService) Create(ctx context.Context, item *core.User) (*core.User, error) {
	return s.repo.Create(ctx, item)
}

func (s *userService) Replace(ctx context.Context, id string, item *core.User) (*core.User, error) {
	return s.repo.Replace(ctx, id, item)
}

func (s *userService) Delete(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}
