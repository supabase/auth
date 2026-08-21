package scim

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

var ErrNotFound = errors.New("scim: resource not found")

// Store holds the resources of every tenant this server serves. Scoping it to
// one tenant yields the Repository a handler works with, so a handler cannot
// reach a resource without having named whose it is.
type Store[T any] interface {
	For(tenant string) Repository[T]
}

// Repository is one tenant's collection of one resource type. A server that
// serves a single tenant implements this directly and never sees a tenant.
type Repository[T any] interface {
	Get(ctx context.Context, id string) (T, error)

	// List returns one page of the collection, and the number of resources the
	// query matched.
	//
	// The order MUST be total. StartIndex and Count are a window over that
	// order, and a window over a partial order silently skips and repeats
	// resources between pages, so an implementation orders by the attribute
	// the query names and breaks every remaining tie on id.
	//
	// A Count of zero returns no resources and the total, per Table 6 of
	// RFC 7644, Section 3.4.2.4. total counts every resource the query
	// matched, never the resources on the page.
	//
	// A SortBy the implementation cannot order is a *protocol.Error carrying
	// "invalidValue".
	List(ctx context.Context, query *protocol.SearchRequest) (items []T, total int, err error)

	// Create stores a new resource and returns it as stored, with the identity
	// and metadata the server assigned. A value that violates a uniqueness
	// constraint is a *protocol.Error carrying "uniqueness".
	Create(ctx context.Context, item T) (T, error)

	// Replace overwrites the attributes of the resource with id, keeping its
	// identity and creation metadata. An unknown id is ErrNotFound.
	Replace(ctx context.Context, id string, item T) (T, error)

	// Patch applies a PatchOp to the resource with id and returns it. An unknown
	// id is ErrNotFound.
	Patch(ctx context.Context, id string, patch *protocol.PatchOp) (T, error)

	// Delete removes the resource with id from every read. An unknown id is
	// ErrNotFound.
	Delete(ctx context.Context, id string) error
}

// Notes for an implementation backed by Postgres, gathered while shaping this
// interface:
//
//   - Write the SQL. RawQuery is the idiom throughout internal/models, and pop
//     is only the struct scanner on the end of it. Query.Paginate cannot express
//     a SCIM window in any case, being page based where "startIndex=7&count=10"
//     is offset 6 of limit 10, and a PerPage of zero divides by zero inside pop
//     while a Count of zero is a legal SCIM query.
//   - SortBy must never reach a query as text. Resolve it against the schema to
//     a column this server knows, and report an unresolved one as
//     "invalidValue".
//   - Keyset pagination is not available here, unlike
//     models.FindUsersInAudienceKeyset. "totalResults" is REQUIRED and
//     "startIndex" is an absolute index a client may jump to, so both the COUNT
//     and the OFFSET are unavoidable.

// UserStore stores the User resources of RFC 7643, Section 4.1.
type UserStore = Store[*core.User]

// NewMemoryUserStore holds Users in memory, ordered by the attributes a client
// may sort them on.
func NewMemoryUserStore() *MemoryStore[*core.User] {
	return NewMemoryStore(
		func(u *core.User) string { return u.ID },
		map[string]func(a, b *core.User) int{
			"id":                byText(func(u *core.User) string { return u.ID }),
			"userName":          byFoldedText(func(u *core.User) string { return u.UserName }),
			"meta.created":      byTime(func(u *core.User) time.Time { return u.Meta.Created }),
			"meta.lastModified": byTime(func(u *core.User) time.Time { return u.Meta.LastModified }),
		},
		filterUsers,
		MemoryWrites[*core.User]{
			Created: func(u *core.User) *core.User {
				stored := cloneUser(u)
				stored.ID = uuid.Must(uuid.NewV4()).String()
				now := time.Now().UTC()
				stored.Meta = core.Meta{ResourceType: core.KindUser.Name, Created: now, LastModified: now}
				return stored
			},
			Replaced: func(existing, incoming *core.User) *core.User {
				stored := cloneUser(incoming)
				stored.ID = existing.ID
				stored.Meta = existing.Meta
				stored.Meta.LastModified = time.Now().UTC()
				return stored
			},
			Patched: func(existing *core.User, patch *protocol.PatchOp) (*core.User, error) {
				patched, err := applyUserPatch(existing, patch)
				if err != nil {
					return nil, err
				}
				patched.Meta.LastModified = time.Now().UTC()
				return patched, nil
			},
		},
	)
}

// cloneUser is a deep copy through the resource's own JSON, which also
// canonicalises it, matching how the Postgres store re-marshals a User before
// storing it.
func cloneUser(u *core.User) *core.User {
	clone := new(core.User)
	if encoded, err := json.Marshal(u); err == nil {
		_ = json.Unmarshal(encoded, clone)
	}
	return clone
}

// MemoryStore holds every tenant's resources in a map. It serves development
// and tests, so it orders and windows in memory; a store backed by a database
// pushes both into the query.
// MemoryWrites is the resource-specific behaviour a MemoryStore needs to serve
// writes: how to stamp a new resource with an identity, how to carry that
// identity forward across a replace, and how to apply a patch. The store owns
// the map; these own what a resource of type T becomes as it is written.
type MemoryWrites[T any] struct {
	Created  func(item T) T
	Replaced func(existing, incoming T) T
	Patched  func(existing T, patch *protocol.PatchOp) (T, error)
}

type MemoryStore[T any] struct {
	mu       sync.RWMutex
	byTenant map[string]map[string]T
	idOf     func(T) string
	sorts    map[string]func(a, b T) int
	filter   func(items []T, filter protocol.Filter) ([]T, error)
	writes   MemoryWrites[T]
}

// NewMemoryStore builds a store that identifies a resource with idOf, orders one
// by each attribute named in sorts, and narrows a collection to a parsed filter
// with filter. An attribute absent from sorts is one this store refuses to sort
// by; a filter this store cannot serve is filter's to reject. Attribute names
// are matched without regard to case, as RFC 7643, Section 2.1 requires.
func NewMemoryStore[T any](
	idOf func(T) string,
	sorts map[string]func(a, b T) int,
	filter func(items []T, filter protocol.Filter) ([]T, error),
	writes MemoryWrites[T],
) *MemoryStore[T] {
	folded := make(map[string]func(a, b T) int, len(sorts))
	for name, sort := range sorts {
		folded[strings.ToLower(name)] = sort
	}

	return &MemoryStore[T]{
		byTenant: make(map[string]map[string]T),
		idOf:     idOf,
		sorts:    folded,
		filter:   filter,
		writes:   writes,
	}
}

func (s *MemoryStore[T]) For(tenant string) Repository[T] {
	return &memoryRepository[T]{store: s, tenant: tenant}
}

// Put seeds a tenant's resources. The tenant is named here because a store
// spans tenants; reads go through For, which cannot omit it.
func (s *MemoryStore[T]) Put(tenant string, item T) {
	s.mu.Lock()
	defer s.mu.Unlock()

	items, ok := s.byTenant[tenant]
	if !ok {
		items = make(map[string]T)
		s.byTenant[tenant] = items
	}
	items[s.idOf(item)] = item
}

// order is the total order the query asks for: the named attribute first, then
// id to break every tie it leaves. Descending reverses the whole comparison,
// which keeps the order total rather than only reversing the groups.
func (s *MemoryStore[T]) order(query *protocol.SearchRequest) (func(a, b T) int, error) {
	byID := func(a, b T) int { return strings.Compare(s.idOf(a), s.idOf(b)) }

	primary := byID
	if query.SortBy != "" {
		sort, ok := s.sorts[strings.ToLower(query.SortBy)]
		if !ok {
			return nil, protocol.ErrInvalidValue(strconv.Quote(query.SortBy) +
				" is not an attribute this resource can be sorted by")
		}
		primary = sort
	}

	ordered := func(a, b T) int {
		if order := primary(a, b); order != 0 {
			return order
		}
		return byID(a, b)
	}

	if query.Descending() {
		return func(a, b T) int { return -ordered(a, b) }, nil
	}
	return ordered, nil
}

// memoryRepository is one tenant's view of a MemoryStore.
type memoryRepository[T any] struct {
	store  *MemoryStore[T]
	tenant string
}

func (r *memoryRepository[T]) Get(ctx context.Context, id string) (T, error) {
	r.store.mu.RLock()
	defer r.store.mu.RUnlock()

	if item, ok := r.store.byTenant[r.tenant][id]; ok {
		return item, nil
	}

	var zero T
	return zero, ErrNotFound
}

func (r *memoryRepository[T]) List(ctx context.Context, query *protocol.SearchRequest) ([]T, int, error) {
	order, err := r.store.order(query)
	if err != nil {
		return nil, 0, err
	}

	filter, err := parseFilterQuery(query)
	if err != nil {
		return nil, 0, err
	}

	r.store.mu.RLock()
	defer r.store.mu.RUnlock()

	items := slices.Collect(maps.Values(r.store.byTenant[r.tenant]))

	if filter != nil {
		items, err = r.store.filter(items, filter)
		if err != nil {
			return nil, 0, err
		}
	}

	// total counts the resources the filter matched, not the tenant's whole
	// collection, because that is what a page is a window over.
	total := len(items)

	// A count of none is answered with the total alone. Here that only saves
	// ordering a whole tenant to return nothing, and no test can tell the
	// difference; for a store backed by SQL it is a requirement, because a
	// limit of zero is not a query worth issuing and pop divides by it.
	if query.Count <= 0 {
		return nil, total, nil
	}

	slices.SortFunc(items, order)

	offset := query.Offset()
	if offset >= total {
		return nil, total, nil
	}

	return items[offset:min(offset+query.Count, total)], total, nil
}

func (r *memoryRepository[T]) Create(ctx context.Context, item T) (T, error) {
	stored := r.store.writes.Created(item)
	r.store.Put(r.tenant, stored)
	return stored, nil
}

func (r *memoryRepository[T]) Replace(ctx context.Context, id string, item T) (T, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()

	existing, ok := r.store.byTenant[r.tenant][id]
	if !ok {
		var zero T
		return zero, ErrNotFound
	}

	stored := r.store.writes.Replaced(existing, item)
	r.store.byTenant[r.tenant][id] = stored
	return stored, nil
}

func (r *memoryRepository[T]) Patch(ctx context.Context, id string, patch *protocol.PatchOp) (T, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()

	existing, ok := r.store.byTenant[r.tenant][id]
	if !ok {
		var zero T
		return zero, ErrNotFound
	}

	patched, err := r.store.writes.Patched(existing, patch)
	if err != nil {
		var zero T
		return zero, err
	}
	r.store.byTenant[r.tenant][id] = patched
	return patched, nil
}

func (r *memoryRepository[T]) Delete(ctx context.Context, id string) error {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()

	if _, ok := r.store.byTenant[r.tenant][id]; !ok {
		return ErrNotFound
	}
	delete(r.store.byTenant[r.tenant], id)
	return nil
}

func byText[T any](text func(T) string) func(a, b T) int {
	return func(a, b T) int { return strings.Compare(text(a), text(b)) }
}

// byFoldedText orders an attribute that is not caseExact. RFC 7644,
// Section 3.4.2.3 sorts such an attribute without regard to case, and sorts a
// caseExact one by code point.
func byFoldedText[T any](text func(T) string) func(a, b T) int {
	return func(a, b T) int {
		return strings.Compare(strings.ToLower(text(a)), strings.ToLower(text(b)))
	}
}

func byTime[T any](at func(T) time.Time) func(a, b T) int {
	return func(a, b T) int { return at(a).Compare(at(b)) }
}
