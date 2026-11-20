package crypto

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/crypto/bcrypt"
)

// ErrPasswordHashNotPermitted is returned when a stored password hash uses an
// algorithm, or algorithm parameters, that the server configuration does not
// permit. The user must reset their password to continue.
var ErrPasswordHashNotPermitted = errors.New("crypto: password hash is not permitted by server configuration")

func exceeds(limit, value uint64) bool {
	return limit > 0 && value > limit
}

// CheckPasswordHashPolicy returns ErrPasswordHashNotPermitted (wrapped with the reason) if the
// hash violates the policy. It only parses the hash and never performs the
// expensive hashing, so it is safe to call before CompareHashAndPassword.
// Hashes that cannot be parsed are not rejected here; verifying them fails on
// its own. A nil policy permits everything.
func CheckPasswordHashPolicy(hash string, p *conf.PasswordHashPolicy) error {
	if p == nil {
		return nil
	}

	notPermitted := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrPasswordHashNotPermitted, fmt.Sprintf(format, args...))
	}

	switch {
	case strings.HasPrefix(hash, Argon2Prefix):
		input, err := ParseArgon2Hash(hash)
		if err != nil {
			return nil
		}
		limits := p.Argon2
		if limits == nil {
			if p.Allowlist {
				return notPermitted("algorithm argon2 is not allowed")
			}
			return nil
		}
		if limits.Disabled {
			return notPermitted("algorithm argon2 is disabled")
		}
		if len(limits.Variants) > 0 && !slices.Contains(limits.Variants, input.alg) {
			return notPermitted("argon2 variant %s is not allowed", input.alg)
		}
		if exceeds(limits.MaxMemoryKiB, input.memory) {
			return notPermitted("%s m=%d exceeds %d", input.alg, input.memory, limits.MaxMemoryKiB)
		}
		if exceeds(limits.MaxTime, input.time) {
			return notPermitted("%s t=%d exceeds %d", input.alg, input.time, limits.MaxTime)
		}
		if exceeds(limits.MaxThreads, input.threads) {
			return notPermitted("%s p=%d exceeds %d", input.alg, input.threads, limits.MaxThreads)
		}

	case strings.HasPrefix(hash, FirebaseScryptPrefix):
		input, err := ParseFirebaseScryptHash(hash)
		if err != nil {
			return nil
		}
		limits := p.FirebaseScrypt
		if limits == nil {
			if p.Allowlist {
				return notPermitted("algorithm fbscrypt is not allowed")
			}
			return nil
		}
		if limits.Disabled {
			return notPermitted("algorithm fbscrypt is disabled")
		}
		// memory is stored as 1<<n; recover n.
		var memoryCost uint64
		for m := input.memory; m > 1; m >>= 1 {
			memoryCost++
		}
		if exceeds(limits.MaxMemoryCostLog2, memoryCost) {
			return notPermitted("fbscrypt n=%d exceeds %d", memoryCost, limits.MaxMemoryCostLog2)
		}
		if exceeds(limits.MaxRounds, input.rounds) {
			return notPermitted("fbscrypt r=%d exceeds %d", input.rounds, limits.MaxRounds)
		}
		if exceeds(limits.MaxThreads, input.threads) {
			return notPermitted("fbscrypt p=%d exceeds %d", input.threads, limits.MaxThreads)
		}

	default:
		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil {
			return nil
		}
		if p.Bcrypt == nil {
			if p.Allowlist {
				return notPermitted("algorithm bcrypt is not allowed")
			}
			return nil
		}
		if p.Bcrypt.Disabled {
			return notPermitted("algorithm bcrypt is disabled")
		}
		if p.Bcrypt.MaxCost > 0 && cost > p.Bcrypt.MaxCost {
			return notPermitted("bcrypt cost=%d exceeds %d", cost, p.Bcrypt.MaxCost)
		}
	}

	return nil
}
