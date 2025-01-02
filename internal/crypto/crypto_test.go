package crypto

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
)

func TestEncryptedString(t *testing.T) {
	id := uuid.Must(uuid.NewV4()).String()

	es, err := NewEncryptedString(id, []byte("data"), "key-id", "pwFoiPyybQMqNmYVN0gUnpbfpGQV2sDv9vp0ZAxi_Y4")
	assert.NoError(t, err)

	assert.Equal(t, es.KeyID, "key-id")
	assert.Equal(t, es.Algorithm, "aes-gcm-hkdf")
	assert.Len(t, es.Data, 20)
	assert.Len(t, es.Nonce, 12)

	dec := ParseEncryptedString(es.String())

	assert.NotNil(t, dec)
	assert.Equal(t, dec.Algorithm, "aes-gcm-hkdf")
	assert.Len(t, dec.Data, 20)
	assert.Len(t, dec.Nonce, 12)

	decrypted, err := dec.Decrypt(id, map[string]string{
		"key-id": "pwFoiPyybQMqNmYVN0gUnpbfpGQV2sDv9vp0ZAxi_Y4",
	})

	assert.NoError(t, err)
	assert.Equal(t, []byte("data"), decrypted)
}

func TestSecureToken(t *testing.T) {
	secureToken := SecureToken()
	secureTokenTwo := SecureToken()
	// token must be decoded to check length, we could use base64.RawURLEncoding.DecodedLen
	decodedToken, err := base64.RawURLEncoding.DecodeString(secureToken)
	assert.NoError(t, err, "Token should be base64 URL encoded")
	assert.Len(t, decodedToken, 16, "Tokens should be generated with default length of 16")
	assert.NotEqual(t, secureToken, secureTokenTwo, "Tokens MUST always be random")

	// test custom length
	secureToken = SecureToken(32)
	// token must be decoded to check length, we could use base64.RawURLEncoding.DecodedLen
	decodedToken, err = base64.RawURLEncoding.DecodeString(secureToken)
	assert.NoError(t, err, "Token should be base64 URL encoded")
	assert.Len(t, decodedToken, 32, "Tokens should be generated with default length of 16")
}

func TestGenerateOTP(t *testing.T) {
	otp, err := GenerateOtp(5)
	assert.NoError(t, err)
	assert.NotEmpty(t, otp, "Empty OTP generated")
	assert.Len(t, otp, 5, "OTP generated to unexpected length")
}

type signatureTestCase struct {
	name        string
	id          uuid.UUID
	secrets     []string
	data        []byte
	shouldPass  bool
	expectedErr string
}

func TestGenerateSignatures(t *testing.T) {
	testCases := []signatureTestCase{
		{
			name:       "Valid signature",
			id:         uuid.Must(uuid.NewV4()),
			secrets:    []string{fmt.Sprintf("v1,%s", base64.StdEncoding.EncodeToString([]byte("randomsecret")))},
			shouldPass: true,
		},
		{
			name:        "Invalid secret prefix",
			id:          uuid.Must(uuid.NewV4()),
			secrets:     []string{base64.StdEncoding.EncodeToString([]byte("randomsecret"))},
			shouldPass:  false,
			expectedErr: "invalid signature format",
		},
		{
			name:        "Invalid secret encoding",
			id:          uuid.Must(uuid.NewV4()),
			secrets:     []string{"v1,random secret"},
			shouldPass:  false,
			expectedErr: "unable to create webhook, err: illegal base64 data at input byte 6",
		},
	}
	currentTime := time.Now()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signatureList, err := GenerateSignatures(tc.secrets, tc.id, currentTime, tc.data)
			if tc.shouldPass {
				assert.NoError(t, err)
				assert.Len(t, signatureList, 1)
				assert.NotEqual(t, signatureList[0], tc.secrets[0])
			} else {
				assert.Error(t, err, "Expected test case to fail, but it passed")
				if tc.expectedErr != "" {
					assert.Equal(t, tc.expectedErr, err.Error(), "Expected error doesn't match")
				}
			}
		})
	}
}
