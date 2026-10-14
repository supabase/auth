package scim

import (
	"context"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/api/scim/store"
	"github.com/supabase/auth/internal/ctxkey"
)

var writeKey = ctxkey.New[*write]("scim_write")

type write struct {
	touched query.Touched
	saved   bool
}

func (w *write) scope(links []store.Link) []store.Link {
	if w == nil {
		return links
	}
	kept := []store.Link{}
	for _, link := range links {
		if values, ok := w.touched[link.Attribute]; ok {
			link.Only = values
			kept = append(kept, link)
		}
	}
	return kept
}

type service[T core.Resource] struct {
	server.Service[T]
	references []query.Reference
}

func (r *repository[T]) wrap(inner server.Service[T]) server.Service[T] {
	return service[T]{inner, r.references}
}

func (s service[T]) Patch(ctx context.Context, req *protocol.PatchRequest) (T, error) {
	touched := query.Touches(s.references, req.Operations)
	if touched == nil {
		return s.Service.Patch(ctx, req)
	}
	w := &write{touched: touched}
	item, err := s.Service.Patch(writeKey.WithValue(ctx, w), req)
	if err != nil || w.saved {
		return item, err
	}
	return s.Get(ctx, req.ID)
}

func (s service[T]) Delete(ctx context.Context, req *protocol.DeleteRequest) error {
	return s.Service.Delete(writeKey.WithValue(ctx, &write{touched: query.Touched{}}), req)
}
