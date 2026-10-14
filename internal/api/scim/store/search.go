package store

import "github.com/supabase/auth/internal/api/scim/query"

type Search struct {
	query.Search
	Count  int
	Offset int
}
