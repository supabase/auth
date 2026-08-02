package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
)

const PKCEInvalidCodeChallengeError = "code challenge does not match previously saved code verifier"
const PKCEInvalidCodeMethodError = "code challenge method not supported"

// VerifyPKCEChallenge performs PKCE verification using the provided challenge, method, and verifier.
// Only S256 is supported per OAuth 2.1 (draft-ietf-oauth-v2-1-12, Section 4.1.1).
// The plain method is explicitly excluded: the code_challenge is transmitted in
// the authorization URL and may appear in server logs, browser history, or Referer
// headers — with plain, that leaks the code_verifier directly.
func VerifyPKCEChallenge(codeChallenge, codeChallengeMethod, codeVerifier string) error {
	switch strings.ToLower(codeChallengeMethod) {
	case "s256":
		hashedCodeVerifier := sha256.Sum256([]byte(codeVerifier))
		encodedCodeVerifier := base64.RawURLEncoding.EncodeToString(hashedCodeVerifier[:])
		if subtle.ConstantTimeCompare([]byte(codeChallenge), []byte(encodedCodeVerifier)) != 1 {
			return errors.New(PKCEInvalidCodeChallengeError)
		}
	default:
		return errors.New(PKCEInvalidCodeMethodError)
	}
	return nil
}
