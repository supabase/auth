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
		if !reference.Inverse() {
			links = append(links, Link{
				Attribute: reference.Name,
				Types:     reference.Types(),
				Values:    document.Get(reference.Name),
			})
		}
		document.Remove(reference.Name)
	}
	raw, err := json.Marshal(document)
	return string(raw), links, err
}

func Decode[T core.Resource](rows []Row) ([]T, error) {
	items := make([]T, len(rows))
	for i, row := range rows {
		item, err := row.Into[T]()
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
