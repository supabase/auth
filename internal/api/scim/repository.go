package scim

import (
	"context"
	"errors"

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
