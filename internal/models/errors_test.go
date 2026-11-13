package models

import (
	"fmt"
	"testing"

	"github.com/jackc/pgconn"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestIsUniqueConstraintViolatedError(t *testing.T) {
	require.True(t, IsUniqueConstraintViolatedError(UserEmailUniqueConflictError{}), "should recognize the package's own conflict error")

	pgErr := &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint"}
	require.True(t, IsUniqueConstraintViolatedError(pgErr), "should recognize a raw Postgres unique_violation")
	require.True(t, IsUniqueConstraintViolatedError(errors.Wrap(pgErr, "creating identity")), "should recognize a wrapped Postgres unique_violation")

	otherPgErr := &pgconn.PgError{Code: "23503", Message: "foreign key violation"}
	require.False(t, IsUniqueConstraintViolatedError(otherPgErr), "a different Postgres error code must not be treated as a unique violation")

	require.False(t, IsUniqueConstraintViolatedError(fmt.Errorf("some other error")), "an unrelated error must not be treated as a unique violation")
	require.False(t, IsUniqueConstraintViolatedError(nil), "a nil error must not be treated as a unique violation")
}
