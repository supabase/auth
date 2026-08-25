package scim

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSCIMToken(t *testing.T) {
	token, digest := NewToken()

	t.Run("marks the token so that one is recognisable", func(t *testing.T) {
		assert.Regexp(t, `^scim_`, token)
	})

	t.Run("carries 160 bits of randomness", func(t *testing.T) {
		assert.Regexp(t, `^scim_[a-z2-7]{32}$`, token)
	})

	t.Run("returns the SHA-256 digest of the token", func(t *testing.T) {
		sum := sha256.Sum256([]byte(token))

		assert.Equal(t, hex.EncodeToString(sum[:]), digest)
	})

	t.Run("never leaves the token inside the digest", func(t *testing.T) {
		assert.NotContains(t, digest, token)
	})

	t.Run("produces a digest the table will accept", func(t *testing.T) {
		assert.Regexp(t, `^[0-9a-f]{64}$`, digest,
			"scim_tokens_token_hash_check refuses anything else")
	})

	t.Run("mints a different token every time", func(t *testing.T) {
		other, otherDigest := NewToken()

		assert.NotEqual(t, token, other)
		assert.NotEqual(t, digest, otherDigest)
	})
}
