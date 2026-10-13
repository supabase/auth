package store

import (
	"slices"
	"strconv"
	"uuid"

	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/scim/query"
	"github.com/supabase/auth/internal/storage"
)

type Link struct {
	Attribute string
	Types     []string
	Values    any
}

func (s Scope) link(tx *storage.Connection, source uuid.UUID, l Link) error {
	attribute := l.Attribute
	wanted, err := linkTargets(attribute, l.Values)
	if err != nil {
		return err
	}
	current, err := s.findTargets(tx, source, attribute)
	if err != nil {
		return err
	}
	add, remove := linkDiff(current, wanted)
	if err := s.nestable(tx, source, attribute, add); err != nil {
		return err
	}
	added, err := s.addReferences(tx, source, attribute, l.Types, add)
	if err != nil {
		return err
	}
	found := make(map[uuid.UUID]bool, len(added))
	for _, id := range added {
		found[id] = true
	}
	if i := slices.IndexFunc(add, func(id uuid.UUID) bool { return !found[id] }); i >= 0 {
		return linkInvalid(attribute, add[i].String())
	}
	return s.removeReferences(tx, source, attribute, remove)
}

func (s Scope) nestable(tx *storage.Connection, source uuid.UUID, attribute string, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	ancestors, err := s.findAncestors(tx, source, attribute)
	if err != nil {
		return err
	}
	level := 1
	for _, ancestor := range ancestors {
		level = max(level, ancestor.Longest+1)
	}
	for _, target := range targets {
		if target == source || slices.ContainsFunc(ancestors, func(ancestor Ancestor) bool { return ancestor.SourceID == target }) {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " would make " + attribute + " cyclic")
		}
	}
	height, err := s.depth(tx, targets, attribute)
	if err != nil {
		return err
	}
	if height > 0 && level+height > query.MaxDepth {
		return scimerrors.ErrInvalidValue(attribute + " would nest more than " + strconv.Itoa(query.MaxDepth) + " levels deep")
	}
	return nil
}

func linkTargets(attribute string, raw any) ([]uuid.UUID, error) {
	elements, _ := raw.([]any)
	wanted := make([]uuid.UUID, 0, len(elements))
	for _, element := range elements {
		value, _ := element.(map[string]any)["value"].(string)
		id, err := uuid.Parse(value)
		if err != nil {
			return nil, linkInvalid(attribute, value)
		}
		wanted = append(wanted, id)
	}
	return wanted, nil
}

func linkInvalid(attribute, value string) error {
	return scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a valid " + attribute + " value")
}

func linkDiff(current, wanted []uuid.UUID) (add, remove []uuid.UUID) {
	have := make(map[uuid.UUID]bool, len(current))
	for _, id := range current {
		have[id] = true
	}
	for _, id := range wanted {
		if _, ok := have[id]; !ok {
			add = append(add, id)
		}
		have[id] = false
	}
	for id, stale := range have {
		if stale {
			remove = append(remove, id)
		}
	}
	return add, remove
}
