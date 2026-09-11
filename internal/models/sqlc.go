package models

import (
	"errors"

	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/dbsql/sqlcgen"
)

// sqlQueries returns a sqlc-generated Queries value bound to tx's current
// executor, so statements run on the same connection or transaction as any
// surrounding pop calls.
func sqlQueries(tx *storage.Connection) (*sqlcgen.Queries, error) {
	dbtx, ok := tx.SQLExecutor()
	if !ok {
		return nil, errors.New("models: unable to obtain a sql executor from the storage connection")
	}
	return sqlcgen.New(dbtx), nil
}
