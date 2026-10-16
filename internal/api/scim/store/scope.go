package store

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/gobuffalo/pop/v6"
	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
	"github.com/supabase-community/scim-go/pkg/store"
	"github.com/supabase/auth/internal/storage"
)

const queryTimeout = 5 * time.Second

type edge struct {
	Source    uuid.UUID `db:"source_id"`
	Attribute string    `db:"attribute"`
	Target    uuid.UUID `db:"target_id"`
}

type scope struct {
	*Store
	providerID uuid.UUID
}

type body struct {
	Kind     string          `db:"resource_type"`
	Resource json.RawMessage `db:"resource"`
}

func (sc scope) acyclic(tx *storage.Connection, source uuid.UUID, attribute string, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	cyclic := []uuid.UUID{}
	err := tx.RawQuery(
		selectCycle,
		source, attribute, targets,
	).All(&cyclic)
	if err != nil {
		return errors.Wrap(err, "error finding SCIM cycles")
	}
	if len(cyclic) > 0 {
		return scimerrors.ErrInvalidValue(strconv.Quote(cyclic[0].String()) + " would make " + attribute + " cyclic")
	}
	return nil
}

func (sc scope) edges(tx *storage.Connection, id uuid.UUID) ([]edge, error) {
	edges := []edge{}
	err := tx.RawQuery(selectEdges, id, id).All(&edges)
	return edges, errors.Wrap(err, "error finding SCIM edges")
}

func others(id uuid.UUID, edges []edge) []string {
	ends := make([]string, len(edges))
	for i, e := range edges {
		ends[i] = e.Source.String()
		if e.Source == id {
			ends[i] = e.Target.String()
		}
	}
	return ends
}

// RFC 7232 Section 2.1: a weak entity tag changes when the representation changes.
func (sc scope) bump(tx *storage.Connection, source uuid.UUID, ids []string) error {
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == source.String() })
	if len(ids) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(bumpResources, sc.providerID, ids).Exec(), "error bumping SCIM versions")
}

func (sc scope) find(tx *storage.Connection, id uuid.UUID, refs []store.Reference) (store.Record, error) {
	rows, err := sc.fetch(tx, selection(refs), resourceByID, id, sc.providerID, sc.Type)
	if err != nil {
		return store.Record{}, err
	}
	if len(rows) == 0 {
		return store.Record{}, notFound()
	}
	return rows[0].record(), nil
}

func (sc scope) fetch(tx *storage.Connection, selection, from string, args ...any) ([]model, error) {
	rows := []model{}
	err := tx.RawQuery(fmt.Sprintf(selectResources, selection, from), args...).All(&rows)
	return rows, err
}

func (sc scope) remove(tx *storage.Connection, id uuid.UUID, version string) error {
	ends, err := sc.edges(tx, id)
	if err != nil {
		return err
	}
	count, err := tx.RawQuery(
		softDeleteResource,
		id, sc.providerID, sc.Type, versionTime(version),
	).ExecWithCount()
	if err != nil {
		return errors.Wrap(err, "error deleting SCIM resource")
	}
	if count == 0 {
		return store.ErrNoMatch
	}
	if err := sc.unlink(tx, id, ends); err != nil {
		return err
	}
	return sc.bump(tx, id, others(id, ends))
}

func (sc scope) page(ctx context.Context, request *protocol.SearchRequest, refs []store.Reference) ([]store.Record, int, error) {
	found, err := sc.Search(request)
	if err != nil {
		return nil, 0, err
	}
	q := sc.query(sc.db.conn)
	if found.Where != nil {
		text, args := found.Where.SQL()
		q = q.Where("("+text+")", args...)
	}
	if request.Count == 0 {
		total, err := sc.count(ctx, q)
		return nil, total, err
	}
	offset := request.Offset()
	sql, values := q.Select("id").Order(found.Order, found.OrderArgs...).ToSQL(pop.NewModel(&model{}, ctx))
	bounded, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	rows, err := sc.fetch(sc.db.conn.WithContext(bounded), selection(refs), fmt.Sprintf(pageOfResources, sql, len(values)+1, len(values)+2), append(values, request.Count, offset)...)
	if err != nil {
		return nil, 0, err
	}
	total := offset + len(rows)
	if len(rows) == request.Count || (len(rows) == 0 && offset > 0) {
		total, err = sc.count(ctx, q)
	}
	if err != nil {
		return nil, 0, err
	}
	return records(rows), total, nil
}

func (sc scope) count(ctx context.Context, q *pop.Query) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	bounded := *q
	bounded.Connection = q.Connection.WithContext(ctx)
	return bounded.Count(&model{})
}

func (sc scope) query(tx *storage.Connection) *pop.Query {
	return tx.Q().Where(scopeWhere, sc.providerID, sc.Type)
}

// RFC 7643 Section 2.3.7: a soft link to a deleted resource leaves the source.
func (sc scope) unlink(tx *storage.Connection, target uuid.UUID, edges []edge) error {
	for _, e := range edges {
		if e.Target != target || !sc.db.soft[e.Attribute] {
			continue
		}
		if err := sc.drop(tx, e); err != nil {
			return err
		}
	}
	return nil
}

func (sc scope) drop(tx *storage.Connection, e edge) error {
	var b body
	if err := tx.RawQuery(selectBody, e.Source).First(&b); err != nil {
		return errors.Wrap(err, "error finding SCIM source")
	}
	object := core.Object{}
	if err := json.Unmarshal(b.Resource, &object); err != nil {
		return err
	}
	store.Unlink(sc.db.owners[b.Kind], object, e.Attribute)
	raw, err := json.Marshal(object)
	if err != nil {
		return err
	}
	return errors.Wrap(tx.RawQuery(updateBody, string(raw), e.Source).Exec(), "error unlinking SCIM source")
}

func (sc scope) create(tx *storage.Connection, id uuid.UUID, body []byte, name any) error {
	return tx.RawQuery(
		insertResource,
		id, sc.providerID, sc.Type, string(body), name,
	).Exec()
}

func (sc scope) update(tx *storage.Connection, id uuid.UUID, body []byte, name any, version string) error {
	count, err := tx.RawQuery(
		updateResource,
		string(body), name, id, sc.providerID, sc.Type, versionTime(version),
	).ExecWithCount()
	if err != nil {
		return err
	}
	if count == 0 {
		return store.ErrNoMatch
	}
	return nil
}

func (sc scope) relink(tx *storage.Connection, source uuid.UUID, links []store.Link) error {
	return sc.each(tx, source, links, sc.link)
}

func (sc scope) attach(tx *storage.Connection, source uuid.UUID, links []store.Link) error {
	return sc.each(tx, source, links, sc.add)
}

func (sc scope) each(tx *storage.Connection, source uuid.UUID, links []store.Link, apply func(*storage.Connection, uuid.UUID, store.Link) ([]string, error)) error {
	changed := []string{}
	for _, l := range links {
		touched, err := apply(tx, source, l)
		if err != nil {
			return err
		}
		changed = append(changed, touched...)
	}
	return sc.bump(tx, source, changed)
}

func (sc scope) link(tx *storage.Connection, source uuid.UUID, l store.Link) ([]string, error) {
	current, err := sc.findTargets(tx, source, l.Attribute)
	if err != nil {
		return nil, err
	}
	add, remove := store.LinkDiff(current, l.Targets)
	if !l.Soft {
		if err := sc.acyclic(tx, source, l.Attribute, add); err != nil {
			return nil, err
		}
	}
	if err := sc.connect(tx, source, l, add); err != nil {
		return nil, err
	}
	return append(add, remove...), sc.removeReferences(tx, source, l.Attribute, remove)
}

func (sc scope) add(tx *storage.Connection, source uuid.UUID, l store.Link) ([]string, error) {
	add, _ := store.LinkDiff(nil, l.Targets)
	return add, sc.connect(tx, source, l, add)
}

func (sc scope) connect(tx *storage.Connection, source uuid.UUID, l store.Link, add []string) error {
	added, err := sc.addReferences(tx, source, l.Attribute, l.Types, add)
	if err != nil {
		return err
	}
	if !l.Soft && len(added) < len(add) {
		i := slices.IndexFunc(add, func(id string) bool { return !slices.Contains(added, id) })
		return linkInvalid(l.Attribute, add[i])
	}
	return nil
}

func (sc scope) addReferences(tx *storage.Connection, source uuid.UUID, attribute string, types, targets []string) ([]string, error) {
	added := []uuid.UUID{}
	if len(targets) == 0 {
		return nil, nil
	}
	err := tx.RawQuery(
		insertReferences,
		source, attribute, sc.providerID, types, targets,
	).All(&added)
	return uuidStrings(added), errors.Wrap(err, "error adding SCIM references")
}

func (sc scope) removeReferences(tx *storage.Connection, source uuid.UUID, attribute string, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	return errors.Wrap(tx.RawQuery(
		deleteReferences,
		source, attribute, targets,
	).Exec(), "error removing SCIM references")
}

func (sc scope) findTargets(tx *storage.Connection, source uuid.UUID, attribute string) ([]string, error) {
	targets := []uuid.UUID{}
	err := tx.RawQuery(selectTargets, source, attribute).All(&targets)
	return uuidStrings(targets), errors.Wrap(err, "error finding SCIM targets")
}

func linkInvalid(attribute, value string) error {
	return scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a valid " + attribute + " value")
}

func selection(refs []store.Reference) string {
	if len(refs) == 0 {
		return "resource"
	}
	pairs := make([]string, len(refs))
	for i, ref := range refs {
		pairs[i] = quoteLiteral(ref.Name) + ", " + subquery(ref)
	}
	return "resource || jsonb_strip_nulls(jsonb_build_object(" + strings.Join(pairs, ", ") + "))"
}

func subquery(ref store.Reference) string {
	if ref.Inverse() {
		return fmt.Sprintf(inverseSubquery, quoteLiteral(ref.InverseOf))
	}
	return fmt.Sprintf(memberSubquery, quoteLiteral(ref.Name))
}

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func versionTime(version string) *time.Time {
	t, ok := server.ParseWeakETag(version)
	if !ok {
		return nil
	}
	return &t
}
