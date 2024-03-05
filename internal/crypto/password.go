package crypto

import (
	"context"
	"errors"
	"fmt"

	"github.com/supabase/auth/internal/observability"
	"go.opentelemetry.io/otel/attribute"

	"golang.org/x/crypto/bcrypt"
)

type HashCost = int

const (
	// DefaultHashCost represents the default
	// hashing cost for any hashing algorithm.
	DefaultHashCost HashCost = iota

	// QuickHashCosts represents the quickest
	// hashing cost for any hashing algorithm,
	// useful for tests only.
	QuickHashCost HashCost = iota

	// BCrypt hashed passwords have a 72 character limit
	MaxPasswordLength = 72
)

// PasswordHashCost is the current pasword hashing cost
// for all new hashes generated with
// GenerateHashFromPassword.
var PasswordHashCost = DefaultHashCost

var (
	generateFromPasswordSubmittedCounter = observability.ObtainMetricCounter("gotrue_generate_from_password_submitted", "Number of submitted GenerateFromPassword hashing attempts")
	generateFromPasswordCompletedCounter = observability.ObtainMetricCounter("gotrue_generate_from_password_completed", "Number of completed GenerateFromPassword hashing attempts")
)

var (
	compareHashAndPasswordSubmittedCounter = observability.ObtainMetricCounter("gotrue_compare_hash_and_password_submitted", "Number of submitted CompareHashAndPassword hashing attempts")
	compareHashAndPasswordCompletedCounter = observability.ObtainMetricCounter("gotrue_compare_hash_and_password_completed", "Number of completed CompareHashAndPassword hashing attempts")
)

// CompareHashAndPassword compares the hash and
// password, returns nil if equal otherwise an error. Context can be used to
// cancel the hashing if the algorithm supports it.
func CompareHashAndPassword(ctx context.Context, hash, password string) error {
	hashCost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return err
	}

	attributes := []attribute.KeyValue{
		attribute.String("alg", "bcrypt"),
		attribute.Int("bcrypt_cost", hashCost),
	}

	compareHashAndPasswordSubmittedCounter.Add(ctx, 1, attributes...)
	defer func() {
		attributes = append(attributes, attribute.Bool(
			"match",
			!errors.Is(err, bcrypt.ErrMismatchedHashAndPassword),
		))

		compareHashAndPasswordCompletedCounter.Add(ctx, 1, attributes...)
	}()

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	return err
}

// GenerateFromPassword generates a password hash from a
// password, using PasswordHashCost. Context can be used to cancel the hashing
// if the algorithm supports it.
func GenerateFromPassword(ctx context.Context, password string) (string, error) {
	var hashCost int

	if len(password) > MaxPasswordLength {
		return "", fmt.Errorf("password cannot be longer than %d characters", MaxPasswordLength)
	}

	switch PasswordHashCost {
	case QuickHashCost:
		hashCost = bcrypt.MinCost

	default:
		hashCost = bcrypt.DefaultCost
	}

	attributes := []attribute.KeyValue{
		attribute.String("alg", "bcrypt"),
		attribute.Int("bcrypt_cost", hashCost),
	}

	generateFromPasswordSubmittedCounter.Add(ctx, 1, attributes...)
	defer generateFromPasswordCompletedCounter.Add(ctx, 1, attributes...)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), hashCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}
