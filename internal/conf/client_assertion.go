package conf

import (
	"context"
	"crypto"
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// ClientAssertionConfiguration configures the keys used to sign client
// assertions (private_key_jwt, RFC 7523) that Auth sends to custom OAuth
// providers' token endpoints instead of a client secret.
type ClientAssertionConfiguration struct {
	// Enabled allows custom OAuth providers to use private_key_jwt.
	// Env: GOTRUE_EXPERIMENTAL_CLIENT_ASSERTION_ENABLED=true
	Enabled bool `json:"enabled" default:"false"`

	// Keys is a JWK set in the same format as GOTRUE_JWT_KEYS, used only to
	// sign client assertions. Plain RSA private keys and KMS-backed keys
	// (aws:kms:arn) are supported, and every key must be RS256. As with
	// GOTRUE_JWT_KEYS, the active signing key is the single key with key_ops
	// ["sign"]; other keys are kept for rotation. No key may be shared with
	// GOTRUE_JWT_KEYS. Keys are validated whenever they are set, even if
	// Enabled is false.
	// Env: GOTRUE_EXPERIMENTAL_CLIENT_ASSERTION_KEYS='[{...}]'
	Keys JwtKeysDecoder `json:"-"`

	// Issuer overrides the iss claim of client assertions, which defaults to
	// the provider's client_id. Must not equal GOTRUE_JWT_ISSUER.
	// Env: GOTRUE_EXPERIMENTAL_CLIENT_ASSERTION_ISSUER=https://auth.example.com
	Issuer string `json:"issuer"`

	// SigningJwk is the active key from Keys. Set in ApplyDefaults.
	SigningJwk jwk.Key `ignored:"true" json:"-"`

	// SigningKey returns the key to sign client assertions with. Set in
	// ApplyDefaults.
	SigningKey func(context.Context) (any, error) `ignored:"true" json:"-"`
}

// applyDefaults checks the client assertion keys on their own and sets up the
// active signing key. Checks that need other parts of the configuration are in
// validate.
func (c *ClientAssertionConfiguration) applyDefaults() error {
	c.SigningJwk = nil
	c.SigningKey = nil

	if len(c.Keys) == 0 {
		return nil
	}

	if err := c.Keys.Validate(); err != nil {
		return fmt.Errorf("conf: invalid client assertion keys: %w", err)
	}

	var signingJwk jwk.Key
	for kid, key := range c.Keys {
		if err := validateClientAssertionKey(kid, key.PrivateKey); err != nil {
			return err
		}
		if slices.Contains(key.PrivateKey.KeyOps(), jwk.KeyOpSign) {
			signingJwk = key.PrivateKey
		}
	}

	signingKey, err := getSigningKey(signingJwk)
	if err != nil {
		return fmt.Errorf("conf: client assertion signing key: %w", err)
	}

	c.SigningJwk = signingJwk
	c.SigningKey = signingKey
	return nil
}

func validateClientAssertionKey(kid string, key jwk.Key) error {
	if kid == "" {
		return fmt.Errorf("conf: client assertion keys must have a kid")
	}
	if key.KeyType() != jwa.RSA {
		return fmt.Errorf("conf: client assertion key %q must be an RSA key, got %q", kid, key.KeyType())
	}
	if key.Algorithm().String() != jwa.RS256.String() {
		return fmt.Errorf("conf: client assertion key %q must use alg RS256, got %q", kid, key.Algorithm())
	}

	_, _, isKMS, err := kmsKeyARN(key)
	if err != nil {
		return fmt.Errorf("conf: client assertion key %q: %w", kid, err)
	}
	if isKMS {
		return nil
	}

	if slices.Contains(key.KeyOps(), jwk.KeyOpSign) {
		if _, ok := key.(jwk.RSAPrivateKey); !ok {
			return fmt.Errorf("conf: client assertion signing key %q must be a private key", kid)
		}
	}
	return nil
}

// validate checks the client assertion configuration against the rest of the
// configuration. The assertion keys must never be usable as
// session keys, so they may not share a kid or key material with the JWT keys.
func (c *ClientAssertionConfiguration) validate(jwtConfig *JWTConfiguration) error {
	if c.Issuer != "" && c.Issuer == jwtConfig.Issuer {
		return fmt.Errorf("conf: client assertion issuer must not equal the JWT issuer")
	}

	if len(c.Keys) == 0 {
		if c.Enabled {
			return fmt.Errorf("conf: client assertion is enabled but no client assertion keys are configured")
		}
		return nil
	}

	jwtThumbprints := make(map[string]struct{}, len(jwtConfig.Keys))
	for _, key := range jwtConfig.Keys {
		k := key.PublicKey
		if k == nil {
			k = key.PrivateKey
		}
		tp, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("conf: computing JWT key thumbprint: %w", err)
		}
		jwtThumbprints[string(tp)] = struct{}{}
	}

	for kid, key := range c.Keys {
		if _, ok := jwtConfig.Keys[kid]; ok || kid == jwtConfig.KeyID {
			return fmt.Errorf("conf: client assertion key %q has the same kid as a JWT key", kid)
		}

		tp, err := key.PublicKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("conf: computing client assertion key thumbprint: %w", err)
		}
		if _, ok := jwtThumbprints[string(tp)]; ok {
			return fmt.Errorf("conf: client assertion key %q is also used as a JWT key", kid)
		}
	}

	if c.Enabled && c.SigningKey == nil {
		return fmt.Errorf("conf: client assertion is enabled but no client assertion signing key is configured")
	}

	return nil
}
