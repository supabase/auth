package scim

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/supabase/auth/internal/crypto"
)

const TokenPrefix = "scim_"
const tokenLength = 32

func NewSCIMToken() (token, digest string) {
	token = TokenPrefix + crypto.SecureAlphanumeric(tokenLength)
	return token, hashToken(token)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
