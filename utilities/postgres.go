package utilities

import (
	"errors"
	"strconv"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgerrcode"
)

// PostgresError is a custom error struct for marshalling Postgres errors to JSON.
type PostgresError struct {
	Code           string `json:"code"`
	HttpStatusCode int    `json:"-"`
	Message        string `json:"message"`
	Hint           string `json:"hint,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

// NewPostgresError returns a new PostgresError if the error was from a publicly
// accessible Postgres error.
func NewPostgresError(err error) *PostgresError {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && isPubliclyAccessiblePostgresError(pgErr.Code) {
		return &PostgresError{
			Code:           pgErr.Code,
			HttpStatusCode: getHttpStatusCodeFromPostgresErrorCode(pgErr.Code),
			Message:        pgErr.Message,
			Detail:         pgErr.Detail,
			Hint:           pgErr.Hint,
		}
	}

	return nil
}

// isPubliclyAccessiblePostgresError checks if the Postgres error should be
// made accessible.
func isPubliclyAccessiblePostgresError(code string) bool {
	if len(code) != 5 {
		return false
	}

	if code == pgerrcode.RaiseException {
		return true
	}

	return getHttpStatusCodeFromPostgresErrorCode(code) != 0
}

// getHttpStatusCodeFromPostgresErrorCode maps a Postgres error code to a HTTP
// status code.
func getHttpStatusCodeFromPostgresErrorCode(code string) int {
	if code == pgerrcode.RaiseException {
		return 500
	}

	// Use custom HTTP status code if Postgres error was triggered with `PTXXX`
	// code. This is consistent with PostgREST's behaviour as well.
	if code[0:2] == "PT" {
		if httpStatusCode, err := strconv.ParseInt(code[2:], 10, 0); err == nil {
			return int(httpStatusCode)
		}
	}

	return 0
}
