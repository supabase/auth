package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyPKCEChallenge(t *testing.T) {
	tests := []struct {
		name                string
		codeChallenge       string
		codeChallengeMethod string
		codeVerifier        string
		wantErr             bool
		errMsg              string
	}{
		{
			name:                "valid S256 PKCE",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			wantErr:             false,
		},
		{
			// OAuth 2.1 Section 4.1.1: plain is not supported.
			name:                "plain method rejected",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "plain",
			codeVerifier:        "test-challenge",
			wantErr:             true,
			errMsg:              PKCEInvalidCodeMethodError,
		},
		{
			name:                "invalid S256 verifier",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			codeVerifier:        "wrong-verifier",
			wantErr:             true,
			errMsg:              "code challenge does not match",
		},
		{
			// plain is rejected at method level, not verifier level.
			name:                "plain method rejected even with wrong verifier",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "plain",
			codeVerifier:        "wrong-challenge",
			wantErr:             true,
			errMsg:              PKCEInvalidCodeMethodError,
		},
		{
			name:                "invalid challenge method",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "invalid",
			codeVerifier:        "test-challenge",
			wantErr:             true,
			errMsg:              "code challenge method not supported",
		},
		{
			name:                "case insensitive S256 method",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "s256",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			wantErr:             false,
		},
		{
			// Case-insensitive rejection.
			name:                "PLAIN rejected case-insensitively",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "PLAIN",
			codeVerifier:        "test-challenge",
			wantErr:             true,
			errMsg:              PKCEInvalidCodeMethodError,
		},
		{
			name:                "empty verifier with S256",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			codeVerifier:        "",
			wantErr:             true,
			errMsg:              "code challenge does not match",
		},
		{
			name:                "plain method rejected with empty verifier",
			codeChallenge:       "test-challenge",
			codeChallengeMethod: "plain",
			codeVerifier:        "",
			wantErr:             true,
			errMsg:              PKCEInvalidCodeMethodError,
		},
		{
			name:                "empty challenge with S256",
			codeChallenge:       "",
			codeChallengeMethod: "S256",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			wantErr:             true,
			errMsg:              "code challenge does not match",
		},
		{
			name:                "plain method rejected with empty challenge",
			codeChallenge:       "",
			codeChallengeMethod: "plain",
			codeVerifier:        "test-challenge",
			wantErr:             true,
			errMsg:              PKCEInvalidCodeMethodError,
		},
		{
			name:                "plain method rejected when both empty",
			codeChallenge:       "",
			codeChallengeMethod: "plain",
			codeVerifier:        "",
			wantErr:             true,
			errMsg:              PKCEInvalidCodeMethodError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPKCEChallenge(tt.codeChallenge, tt.codeChallengeMethod, tt.codeVerifier)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
