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

// VerifyPKCEChallenge performs PKCE verification using the provided challenge, method, and verifier
// This is a shared utility function used by both FlowState and OAuthServerAuthorization
// Note: For generating PKCE verifiers and challenges, use golang.org/x/oauth2.GenerateVerifier()
// and oauth2.S256ChallengeFromVerifier() instead of custom implementations
func VerifyPKCEChallenge(codeChallenge, codeChallengeMethod, codeVerifier string) error {
	switch strings.ToLower(codeChallengeMethod) {
	case "s256":
		hashedCodeVerifier := sha256.Sum256([]byte(codeVerifier))
		encodedCodeVerifier := base64.RawURLEncoding.EncodeToString(hashedCodeVerifier[:])
		if subtle.ConstantTimeCompare([]byte(codeChallenge), []byte(encodedCodeVerifier)) != 1 {
			return errors.New(PKCEInvalidCodeChallengeError)
		}
	case "plain":
		if subtle.ConstantTimeCompare([]byte(codeChallenge), []byte(codeVerifier)) != 1 {
			return errors.New(PKCEInvalidCodeChallengeError)
		}
	default:
		return errors.New(PKCEInvalidCodeMethodError)
	}
	return nil
}
