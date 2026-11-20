package conf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

// PasswordHashPolicy limits which password hashing algorithms may be verified
// by the server and the maximum cost parameters they may use. It protects the
// server from spending excessive CPU or memory on verifying imported hashes.
//
// The zero value (variable not set) permits every supported algorithm and
// applies no limits beyond the hard limits built into the hash parsers.
//
// When the policy is loaded from the environment (see Decode) it becomes an
// allowlist: only algorithms that appear in it are permitted, and an algorithm
// that is not mentioned is rejected. Use an empty object, e.g. "bcrypt": {},
// to permit an algorithm without limits.
type PasswordHashPolicy struct {
	// Allowlist rejects algorithms whose entry below is nil. It is set by
	// Decode whenever a policy value is provided.
	Allowlist bool `json:"-"`

	Bcrypt         *BcryptHashPolicy         `json:"bcrypt"`
	Argon2         *Argon2HashPolicy         `json:"argon2"`
	FirebaseScrypt *FirebaseScryptHashPolicy `json:"fbscrypt"`
}

// BcryptHashPolicy limits bcrypt hashes.
type BcryptHashPolicy struct {
	// Disabled rejects every bcrypt hash.
	Disabled bool `json:"disabled"`
	// MaxCost is the maximum bcrypt cost. 0 means no limit.
	MaxCost int `json:"max_cost"`
}

// Argon2 variant names, as used in Argon2HashPolicy.Variants.
const (
	Argon2VariantI  = "argon2i"
	Argon2VariantID = "argon2id"
)

// Argon2HashPolicy limits Argon2 hashes.
type Argon2HashPolicy struct {
	// Disabled rejects every Argon2 hash.
	Disabled bool `json:"disabled"`
	// Variants lists the permitted variants: argon2i and/or argon2id. When
	// omitted, all variants are permitted.
	Variants []string `json:"variants"`
	// MaxMemoryKiB is the maximum memory (m) in KiB. 0 means no limit.
	MaxMemoryKiB uint64 `json:"max_memory_kib"`
	// MaxTime is the maximum number of passes (t). 0 means no limit.
	MaxTime uint64 `json:"max_time"`
	// MaxThreads is the maximum parallelism (p). 0 means no limit.
	MaxThreads uint64 `json:"max_threads"`
}

// FirebaseScryptHashPolicy limits Firebase scrypt hashes.
type FirebaseScryptHashPolicy struct {
	// Disabled rejects every Firebase scrypt hash.
	Disabled bool `json:"disabled"`
	// MaxMemoryCostLog2 is the maximum mem_cost (the "n" parameter, as a
	// power of 2). 0 means no limit.
	MaxMemoryCostLog2 uint64 `json:"max_memory_cost_log2"`
	// MaxRounds is the maximum number of rounds (r). 0 means no limit.
	MaxRounds uint64 `json:"max_rounds"`
	// MaxThreads is the maximum parallelism (p). 0 means no limit.
	MaxThreads uint64 `json:"max_threads"`
}

// passwordHashPolicySchema is the JSON schema every
// GOTRUE_PASSWORD_HASH_COMPUTE_POLICY value must satisfy before it is decoded.
const passwordHashPolicySchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "bcrypt": {
      "type": "object",
      "properties": {
        "disabled": { "type": "boolean" },
        "max_cost": { "type": "integer", "minimum": 0, "maximum": 31 }
      }
    },
    "argon2": {
      "type": "object",
      "properties": {
        "disabled": { "type": "boolean" },
        "variants": {
          "type": "array",
          "uniqueItems": true,
          "minItems": 1,
          "items": { "type": "string" }
        },
        "max_memory_kib": { "type": "integer", "minimum": 0 },
        "max_time": { "type": "integer", "minimum": 0 },
        "max_threads": { "type": "integer", "minimum": 0, "maximum": 255 }
      }
    },
    "fbscrypt": {
      "type": "object",
      "properties": {
        "disabled": { "type": "boolean" },
        "max_memory_cost_log2": { "type": "integer", "minimum": 0, "maximum": 63 },
        "max_rounds": { "type": "integer", "minimum": 0 },
        "max_threads": { "type": "integer", "minimum": 0, "maximum": 255 }
      }
    }
  }
}`

var passwordHashPolicySchemaLoader = gojsonschema.NewStringLoader(passwordHashPolicySchema)

// Decode implements envconfig.Decoder so the whole policy can be provided as a
// single JSON object in one environment variable, e.g.
// GOTRUE_PASSWORD_HASH_COMPUTE_POLICY='{"bcrypt":{"max_cost":10},"argon2":{"variants":["argon2id"]}}'.
// The value is validated against a JSON schema first; wrong types and
// out-of-range values are rejected. Unknown keys are deliberately accepted and
// ignored so that policies written for newer versions still load.
func (p *PasswordHashPolicy) Decode(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	result, err := gojsonschema.Validate(passwordHashPolicySchemaLoader, gojsonschema.NewStringLoader(value))
	if err != nil {
		return fmt.Errorf("conf: invalid password hash compute policy JSON: %w", err)
	}
	if !result.Valid() {
		msgs := make([]string, 0, len(result.Errors()))
		for _, e := range result.Errors() {
			msgs = append(msgs, e.String())
		}
		return fmt.Errorf("conf: password hash compute policy does not match schema: %s", strings.Join(msgs, "; "))
	}

	var parsed PasswordHashPolicy
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		return fmt.Errorf("conf: invalid password hash compute policy JSON: %w", err)
	}
	parsed.Allowlist = true
	*p = parsed
	return nil
}
