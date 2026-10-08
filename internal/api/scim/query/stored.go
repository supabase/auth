package query

import (
	"slices"
	"strconv"

	"github.com/gofrs/uuid"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

type stored struct {
	named
	targets []string
}

func Stored(attribute string, targets ...string) Reference {
	return stored{named: named(attribute), targets: targets}
}

func (s stored) Columns() map[string]string {
	return map[string]string{
		ValueAttribute: "edge.target_id",
		"type":         "lower(target.resource_type)",
	}
}

func (s stored) Exists(inner string, args []any) (string, []any) {
	return "EXISTS (SELECT 1 FROM scim_resource_references edge JOIN scim_resources target ON target.id = edge.target_id AND target.deleted_at IS NULL WHERE edge.source_id = scim_resources.id AND edge.attribute = ? AND " + inner + ")", append([]any{s.Name()}, args...)
}

func (s stored) Extract(attribute any) ([]uuid.UUID, error) {
	elements, _ := attribute.([]any)
	ids := make([]uuid.UUID, 0, len(elements))
	for _, element := range elements {
		value, _ := element.(map[string]any)[ValueAttribute].(string)
		id, err := uuid.FromString(value)
		if err != nil {
			return nil, s.invalidValue(value)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s stored) Link(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, wanted []uuid.UUID) error {
	current, err := scope.FindTargets(tx, source, s.Name())
	if err != nil {
		return err
	}
	add, remove := diff(current, wanted)
	if err := s.acyclic(tx, scope, source, add); err != nil {
		return err
	}
	if err := s.shallow(tx, scope, source, add); err != nil {
		return err
	}
	added, err := scope.AddReferences(tx, source, s.Name(), s.targets, add)
	if err != nil {
		return err
	}
	if i := slices.IndexFunc(add, func(id uuid.UUID) bool { return !slices.Contains(added, id) }); i >= 0 {
		return s.invalidValue(add[i].String())
	}
	return scope.RemoveReferences(tx, source, s.Name(), remove)
}

func (s stored) Load(tx *storage.Connection, scope models.SCIMScope, ids []uuid.UUID, locations map[string]string) (map[uuid.UUID][]any, error) {
	elements := map[uuid.UUID][]any{}
	references, err := scope.FindReferences(tx, ids, s.Name())
	for _, reference := range references {
		elements[reference.SourceID] = append(elements[reference.SourceID], element(reference.TargetID, locations[reference.TargetType], reference.TargetType))
	}
	return elements, err
}

func (s stored) acyclic(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	ancestors, err := scope.FindAncestors(tx, []uuid.UUID{source}, s.Name())
	if err != nil {
		return err
	}
	for _, target := range targets {
		if target == source || slices.ContainsFunc(ancestors, func(ancestor models.SCIMAncestor) bool { return ancestor.SourceID == target }) {
			return scimerrors.ErrInvalidValue(strconv.Quote(target.String()) + " would make " + s.Name() + " cyclic")
		}
	}
	return nil
}

func (s stored) shallow(tx *storage.Connection, scope models.SCIMScope, source uuid.UUID, targets []uuid.UUID) error {
	if len(targets) == 0 {
		return nil
	}
	height, err := scope.Depth(tx, targets, s.Name(), true)
	if err != nil || height == 0 {
		return err
	}
	level, err := scope.Depth(tx, []uuid.UUID{source}, s.Name(), false)
	if err != nil {
		return err
	}
	if level+height > models.SCIMMaxDepth {
		return scimerrors.ErrInvalidValue(s.Name() + " would nest more than " + strconv.Itoa(models.SCIMMaxDepth) + " levels deep")
	}
	return nil
}

func (s stored) invalidValue(value string) error {
	return scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a valid " + s.Name() + " value")
}

func diff(current, wanted []uuid.UUID) (add, remove []uuid.UUID) {
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
