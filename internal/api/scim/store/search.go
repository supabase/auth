package store

import "github.com/supabase/auth/internal/api/scim/query"

type Search struct {
	Where     query.Clause
	Order     string
	OrderArgs []any
	Count     int
	Offset    int
}
