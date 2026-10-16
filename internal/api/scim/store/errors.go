package store

import (
	"strconv"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
	"github.com/pkg/errors"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase-community/scim-go/pkg/server"
)

func conflict(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return err
	}
	switch pg.Code {
	case pgerrcode.UniqueViolation:
		return scimerrors.ErrUniqueness("resource must be unique")
	case pgerrcode.DeadlockDetected:
		return scimerrors.ErrChanged()
	}
	return err
}

func versionTime(version string) *time.Time {
	t, ok := server.ParseWeakETag(version)
	if !ok {
		return nil
	}
	return &t
}

func notFound() error {
	return scimerrors.ErrNotFound("Not found")
}

func linkInvalid(attribute, value string) error {
	return scimerrors.ErrInvalidValue(strconv.Quote(value) + " is not a valid " + attribute + " value")
}
