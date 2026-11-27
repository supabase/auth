package conf

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf/awskmsjwk"
)

func newTestJwk(t *testing.T, raw any, fields map[string]any) jwk.Key {
	t.Helper()
	k, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	for name, value := range fields {
		require.NoError(t, k.Set(name, value))
	}
	return k
}

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func signingFields(kid string) map[string]any {
	return map[string]any{
		jwk.KeyIDKey:     kid,
		jwk.AlgorithmKey: "RS256",
		jwk.KeyOpsKey:    jwk.KeyOperationList{jwk.KeyOpSign},
	}
}

func encodeTestKeys(t *testing.T, keys ...jwk.Key) string {
	t.Helper()
	b, err := json.Marshal(keys)
	require.NoError(t, err)
	return string(b)
}

// newClientAssertionTestConfig returns a config whose JWT keys hold one RSA
// key (kid "session-key"), so the disjointness checks have something to
// compare against.
func newClientAssertionTestConfig(t *testing.T, jwtKey *rsa.PrivateKey) *GlobalConfiguration {
	t.Helper()
	c := &GlobalConfiguration{}
	c.JWT.Issuer = "https://project.example.com/auth/v1"
	require.NoError(t, c.JWT.Keys.Decode(encodeTestKeys(t,
		newTestJwk(t, jwtKey, signingFields("session-key")),
	)))
	return c
}

func applyAndValidateClientAssertion(c *GlobalConfiguration) error {
	if err := c.ApplyDefaults(); err != nil {
		return err
	}
	return c.Experimental.ClientAssertion.validate(&c.JWT)
}

func TestClientAssertionConfig(t *testing.T) {
	jwtKey := newTestRSAKey(t)
	assertionKey := newTestRSAKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("unset and disabled loads unchanged", func(t *testing.T) {
		c := newClientAssertionTestConfig(t, jwtKey)
		require.NoError(t, applyAndValidateClientAssertion(c))
		require.Nil(t, c.Experimental.ClientAssertion.SigningKey)
		require.Nil(t, c.Experimental.ClientAssertion.SigningJwk)
	})

	t.Run("valid plain RSA key", func(t *testing.T) {
		c := newClientAssertionTestConfig(t, jwtKey)
		c.Experimental.ClientAssertion.Enabled = true
		c.Experimental.ClientAssertion.Issuer = "https://assertion-issuer.example.com"
		require.NoError(t, c.Experimental.ClientAssertion.Keys.Decode(encodeTestKeys(t,
			newTestJwk(t, assertionKey, signingFields("assertion-key")),
		)))
		require.NoError(t, applyAndValidateClientAssertion(c))

		require.Equal(t, "assertion-key", c.Experimental.ClientAssertion.SigningJwk.KeyID())
		require.Equal(t, "RS256", GetSigningAlg(c.Experimental.ClientAssertion.SigningJwk).Alg())
		sk, err := c.Experimental.ClientAssertion.SigningKey(context.Background())
		require.NoError(t, err)
		require.True(t, assertionKey.Equal(sk))
	})

	t.Run("active key is the one with sign key_ops", func(t *testing.T) {
		c := newClientAssertionTestConfig(t, jwtKey)
		c.Experimental.ClientAssertion.Enabled = true
		require.NoError(t, c.Experimental.ClientAssertion.Keys.Decode(encodeTestKeys(t,
			newTestJwk(t, newTestRSAKey(t), map[string]any{
				jwk.KeyIDKey:     "old-key",
				jwk.AlgorithmKey: "RS256",
				jwk.KeyOpsKey:    jwk.KeyOperationList{jwk.KeyOpVerify},
			}),
			newTestJwk(t, assertionKey, signingFields("assertion-key")),
		)))
		require.NoError(t, applyAndValidateClientAssertion(c))
		require.Equal(t, "assertion-key", c.Experimental.ClientAssertion.SigningJwk.KeyID())
	})

	t.Run("KMS-backed key", func(t *testing.T) {
		pub := newTestJwk(t, &assertionKey.PublicKey, signingFields("kms-key"))
		require.NoError(t, pub.Set("aws:kms:arn", "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"))

		c := newClientAssertionTestConfig(t, jwtKey)
		c.Experimental.ClientAssertion.Enabled = true
		require.NoError(t, c.Experimental.ClientAssertion.Keys.Decode(encodeTestKeys(t, pub)))
		require.NoError(t, applyAndValidateClientAssertion(c))

		require.Equal(t, awskmsjwk.SigningMethodRS256KMS, GetSigningAlg(c.Experimental.ClientAssertion.SigningJwk))
		sk, err := c.Experimental.ClientAssertion.SigningKey(context.Background())
		require.NoError(t, err)
		require.IsType(t, &awskmsjwk.RS256Key{}, sk)
	})

	rejections := []struct {
		name     string
		keys     func(t *testing.T) []jwk.Key
		enabled  bool
		issuer   string
		contains string
	}{
		{
			name:     "enabled without keys",
			enabled:  true,
			contains: "no client assertion keys are configured",
		},
		{
			name: "HMAC key",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, []byte("0123456789abcdef0123456789abcdef"), map[string]any{
					jwk.KeyIDKey:     "hmac-key",
					jwk.AlgorithmKey: "HS256",
					jwk.KeyOpsKey:    jwk.KeyOperationList{jwk.KeyOpSign},
				})}
			},
			enabled:  true,
			contains: "must be an RSA key",
		},
		{
			name: "HMAC key is rejected even when disabled",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, []byte("0123456789abcdef0123456789abcdef"), map[string]any{
					jwk.KeyIDKey:     "hmac-key",
					jwk.AlgorithmKey: "HS256",
					jwk.KeyOpsKey:    jwk.KeyOperationList{jwk.KeyOpSign},
				})}
			},
			contains: "must be an RSA key",
		},
		{
			name: "EC key",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, ecKey, map[string]any{
					jwk.KeyIDKey:     "ec-key",
					jwk.AlgorithmKey: "ES256",
					jwk.KeyOpsKey:    jwk.KeyOperationList{jwk.KeyOpSign},
				})}
			},
			enabled:  true,
			contains: "must be an RSA key",
		},
		{
			name: "RSA key with a non-RS256 alg",
			keys: func(t *testing.T) []jwk.Key {
				f := signingFields("rs512-key")
				f[jwk.AlgorithmKey] = "RS512"
				return []jwk.Key{newTestJwk(t, assertionKey, f)}
			},
			enabled:  true,
			contains: "must use alg RS256",
		},
		{
			name: "RSA key without alg",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, assertionKey, map[string]any{
					jwk.KeyIDKey:  "no-alg-key",
					jwk.KeyOpsKey: jwk.KeyOperationList{jwk.KeyOpSign},
				})}
			},
			enabled:  true,
			contains: "must use alg RS256",
		},
		{
			name: "key without kid",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, assertionKey, map[string]any{
					jwk.AlgorithmKey: "RS256",
					jwk.KeyOpsKey:    jwk.KeyOperationList{jwk.KeyOpSign},
				})}
			},
			enabled:  true,
			contains: "must have a kid",
		},
		{
			name: "no signing key",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, assertionKey, map[string]any{
					jwk.KeyIDKey:     "verify-only",
					jwk.AlgorithmKey: "RS256",
					jwk.KeyOpsKey:    jwk.KeyOperationList{jwk.KeyOpVerify},
				})}
			},
			enabled:  true,
			contains: "no signing key detected",
		},
		{
			name: "more than one signing key",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{
					newTestJwk(t, assertionKey, signingFields("key-1")),
					newTestJwk(t, newTestRSAKey(t), signingFields("key-2")),
				}
			},
			enabled:  true,
			contains: "multiple signing keys detected",
		},
		{
			name: "signing key is a public key without KMS",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, &assertionKey.PublicKey, signingFields("public-key"))}
			},
			enabled:  true,
			contains: "must be a private key",
		},
		{
			name: "malformed KMS ARN",
			keys: func(t *testing.T) []jwk.Key {
				k := newTestJwk(t, &assertionKey.PublicKey, signingFields("kms-key"))
				require.NoError(t, k.Set("aws:kms:arn", "not-an-arn"))
				return []jwk.Key{k}
			},
			enabled:  true,
			contains: "invalid aws:kms:arn",
		},
		{
			name: "kid shared with a JWT key",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, assertionKey, signingFields("session-key"))}
			},
			enabled:  true,
			contains: "same kid as a JWT key",
		},
		{
			name: "key material shared with a JWT key",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, jwtKey, signingFields("assertion-key"))}
			},
			enabled:  true,
			contains: "also used as a JWT key",
		},
		{
			name: "issuer override equals the JWT issuer",
			keys: func(t *testing.T) []jwk.Key {
				return []jwk.Key{newTestJwk(t, assertionKey, signingFields("assertion-key"))}
			},
			enabled:  true,
			issuer:   "https://project.example.com/auth/v1",
			contains: "must not equal the JWT issuer",
		},
	}

	for _, tc := range rejections {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			c := newClientAssertionTestConfig(t, jwtKey)
			c.Experimental.ClientAssertion.Enabled = tc.enabled
			c.Experimental.ClientAssertion.Issuer = tc.issuer
			if tc.keys != nil {
				require.NoError(t, c.Experimental.ClientAssertion.Keys.Decode(encodeTestKeys(t, tc.keys(t)...)))
			}
			err := applyAndValidateClientAssertion(c)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.contains)
		})
	}
}

func TestClientAssertionConfigFromEnv(t *testing.T) {
	key := newTestJwk(t, newTestRSAKey(t), signingFields("assertion-key"))
	t.Setenv("GOTRUE_EXPERIMENTAL_CLIENT_ASSERTION_ENABLED", "true")
	t.Setenv("GOTRUE_EXPERIMENTAL_CLIENT_ASSERTION_KEYS", encodeTestKeys(t, key))
	t.Setenv("GOTRUE_EXPERIMENTAL_CLIENT_ASSERTION_ISSUER", "https://assertion-issuer.example.com")

	var c ExperimentalConfiguration
	require.NoError(t, envconfig.Process("gotrue_experimental", &c))
	require.True(t, c.ClientAssertion.Enabled)
	require.Equal(t, "https://assertion-issuer.example.com", c.ClientAssertion.Issuer)
	require.Contains(t, c.ClientAssertion.Keys, "assertion-key")
}
