package store

import (
	"encoding/json"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
)

func Encode[T core.Resource](item T, references []query.Reference) (string, []Link, error) {
	document, err := core.NewObject(item)
	if err != nil {
		return "", nil, err
	}
	for _, key := range []string{"id", "meta", "password"} {
		document.Remove(key)
	}
	links := []Link{}
	for _, reference := range references {
		if types := reference.Targets(); types != nil {
			links = append(links, Link{
				Attribute: reference.Name(),
				Types:     types,
				Values:    document.Get(reference.Name()),
				Nested:    reference.Nested(),
			})
		}
		document.Remove(reference.Name())
	}
	raw, err := json.Marshal(document)
	return string(raw), links, err
}

func Decode[T core.Resource](rows []Row, endpoint string) ([]T, error) {
	items := make([]T, len(rows))
	for i, row := range rows {
		item, err := row.Into[T](endpoint)
		if err != nil {
			return nil, err
		}
		items[i] = item
	}
	return items, nil
}

func NotFound() error {
	return scimerrors.ErrNotFound("Not found")
}
