package store

import (
	"context"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/storage"
)

type Tenant func(context.Context) (uuid.UUID, error)

type DB struct {
	conn   *storage.Connection
	tenant Tenant
	owners map[string]core.Schemas
	soft   map[string]bool
}

func New(conn *storage.Connection, tenant Tenant) *DB {
	return &DB{conn: conn, tenant: tenant, owners: map[string]core.Schemas{}, soft: map[string]bool{}}
}

func (d *DB) Store(schemas core.Schemas, location string) store.Store {
	r := query.NewResource(schemas, location)
	d.owners[r.Type] = schemas
	for _, ref := range store.ReferencesOf(schemas) {
		if ref.Soft() {
			d.soft[ref.Name] = true
		}
	}
	return &Store{db: d, Resource: r}
}
