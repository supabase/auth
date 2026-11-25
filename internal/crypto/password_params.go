package crypto

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// NonDefaultHashParameters reports whether the hash was produced with
// anything other than the server's default for newly generated hashes (bcrypt
// at bcrypt.DefaultCost). If it was, it returns the algorithm and its cost
// parameters, suitable for logging. Salts, hashes, keys and other secret
// material are never included.
//
// Hashes that cannot be parsed are reported as not-default with only the
// algorithm family, so that they still show up in logs.
func NonDefaultHashParameters(hash string) (map[string]any, bool) {
	switch {
	case strings.HasPrefix(hash, Argon2Prefix):
		input, err := ParseArgon2Hash(hash)
		if err != nil {
			return map[string]any{"alg": "argon2", "parse_error": true}, true
		}
		return map[string]any{
			"alg":      input.alg,
			"version":  input.v,
			"m":        input.memory,
			"t":        input.time,
			"p":        input.threads,
			"hash_len": len(input.rawHash),
		}, true

	case strings.HasPrefix(hash, FirebaseScryptPrefix):
		input, err := ParseFirebaseScryptHash(hash)
		if err != nil {
			return map[string]any{"alg": "fbscrypt", "parse_error": true}, true
		}
		var memoryCost uint64
		for m := input.memory; m > 1; m >>= 1 {
			memoryCost++
		}
		return map[string]any{
			"alg":      "fbscrypt",
			"version":  input.v,
			"n_log2":   memoryCost,
			"r":        input.rounds,
			"p":        input.threads,
			"hash_len": len(input.rawHash),
		}, true
	}

	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return map[string]any{"alg": "unknown", "parse_error": true}, true
	}
	if cost == bcrypt.DefaultCost {
		return nil, false
	}
	return map[string]any{"alg": "bcrypt", "cost": cost}, true
}
