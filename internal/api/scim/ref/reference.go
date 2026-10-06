package ref

import (
	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type Reference interface {
	query.Reference
	Resolve(schemas core.Schemas) Reference
	Extract(attribute any) ([]uuid.UUID, error)
	Link(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, wanted []uuid.UUID) error
	Load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error)
}

type named string

func (n named) Name() string {
	return string(n)
}

func (n named) canonical(schemas core.Schemas) (named, *core.Attribute) {
	attribute := schemas.Base().Attributes.Lookup(string(n))
	return named(attribute.Name), attribute
}

func element(id uuid.UUID, endpoint, kind string) map[string]any {
	return map[string]any{
		query.ValueAttribute: id.String(),
		"$ref":               endpoint + "/" + id.String(),
		"type":               kind,
	}
}
