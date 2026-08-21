package scim

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
	"github.com/supabase/auth/internal/storage"
)

var ErrNotFound = errors.New("scim: resource not found")

type Repository[T any] interface {
	Get(ctx context.Context, tenant, id string) (T, error)

	// List returns one page of a tenant's resources, and the number of
	// resources the query matched.
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
	List(ctx context.Context, tenant string, query *protocol.SearchRequest) (items []T, total int, err error)
}

// Notes for an implementation backed by Postgres, gathered while shaping this
// interface:
//
//   - models.Pagination cannot express a SCIM window. It is page based, as is
//     pop's Query.Paginate(page, perPage), but "startIndex=7&count=10" is
//     offset 6 of limit 10 and no page of any size begins there.
//   - pop's SQL builder reads Paginator.Offset directly, so setting
//     q.Paginator = &pop.Paginator{PerPage: count, Offset: offset} windows a
//     query arbitrarily, and the same All() fills Paginator.TotalEntriesSize
//     with the total. pop has Query.Limit but no Query.Offset, so this is the
//     only route that stays out of raw SQL.
//   - A PerPage of zero divides by zero inside pop, which computes
//     TotalPages = TotalEntriesSize / PerPage. A Count of zero is a legal SCIM
//     query, so answer it with a count alone and no page query.
//   - SortBy must never reach a query as text. Resolve it against the schema
//     to a column this server knows, and report an unresolved one as
//     "invalidValue".
//   - Keyset pagination is not available here, unlike
//     models.FindUsersInAudienceKeyset. "totalResults" is REQUIRED and
//     "startIndex" is an absolute index a client may jump to, so both the
//     COUNT and the OFFSET are unavoidable.

// UserRepository stores the User resources of RFC 7643, Section 4.1.
type UserRepository = Repository[*core.User]

func NewUserRepository(db *storage.Connection) *MemoryRepository[*core.User] {
	return NewMemoryRepository(
		func(u *core.User) string { return u.ID },
		map[string]func(a, b *core.User) int{
			"id":                byText(func(u *core.User) string { return u.ID }),
			"userName":          byFoldedText(func(u *core.User) string { return u.UserName }),
			"meta.created":      byTime(func(u *core.User) time.Time { return u.Meta.Created }),
			"meta.lastModified": byTime(func(u *core.User) time.Time { return u.Meta.LastModified }),
		},
	)
}

// MemoryRepository holds a tenant's resources in a map. It serves development
// and tests, so it orders and windows in memory; a repository backed by a
// database pushes both into the query.
type MemoryRepository[T any] struct {
	mu       sync.RWMutex
	byTenant map[string]map[string]T
	idOf     func(T) string
	sorts    map[string]func(a, b T) int
}

// NewMemoryRepository builds a repository that identifies a resource with idOf
// and can order one by each attribute named in sorts. An attribute absent from
// sorts is one this repository will refuse to sort by. Attribute names are
// matched without regard to case, as RFC 7643, Section 2.1 requires.
func NewMemoryRepository[T any](idOf func(T) string, sorts map[string]func(a, b T) int) *MemoryRepository[T] {
	folded := make(map[string]func(a, b T) int, len(sorts))
	for name, sort := range sorts {
		folded[strings.ToLower(name)] = sort
	}

	return &MemoryRepository[T]{
		byTenant: make(map[string]map[string]T),
		idOf:     idOf,
		sorts:    folded,
	}
}

func (r *MemoryRepository[T]) Put(tenant string, item T) {
	r.mu.Lock()
	defer r.mu.Unlock()

	items, ok := r.byTenant[tenant]
	if !ok {
		items = make(map[string]T)
		r.byTenant[tenant] = items
	}
	items[r.idOf(item)] = item
}

func (r *MemoryRepository[T]) Get(ctx context.Context, tenant, id string) (T, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if item, ok := r.byTenant[tenant][id]; ok {
		return item, nil
	}

	var zero T
	return zero, ErrNotFound
}

func (r *MemoryRepository[T]) List(ctx context.Context, tenant string, query *protocol.SearchRequest) ([]T, int, error) {
	order, err := r.order(query)
	if err != nil {
		return nil, 0, err
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	items := slices.Collect(maps.Values(r.byTenant[tenant]))
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

// order is the total order the query asks for: the named attribute first, then
// id to break every tie it leaves. Descending reverses the whole comparison,
// which keeps the order total rather than only reversing the groups.
func (r *MemoryRepository[T]) order(query *protocol.SearchRequest) (func(a, b T) int, error) {
	byID := func(a, b T) int { return strings.Compare(r.idOf(a), r.idOf(b)) }

	primary := byID
	if query.SortBy != "" {
		sort, ok := r.sorts[strings.ToLower(query.SortBy)]
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
