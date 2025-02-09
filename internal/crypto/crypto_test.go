package crypto

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	siws "github.com/supabase/auth/internal/utilities/solana"
)

func TestEncryptedStringPositive(t *testing.T) {
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

func TestParseEncryptedStringNegative(t *testing.T) {
	negativeExamples := []string{
		"not-an-encrypted-string",
		// not json
		"{{",
		// not parsable json
		`{"key_id":1}`,
		`{"alg":1}`,
		`{"data":"!!!"}`,
		`{"nonce":"!!!"}`,
		// not valid
		`{}`,
		`{"key_id":"key_id"}`,
		`{"key_id":"key_id","alg":"different","data":"AQAB=","nonce":"AQAB="}`,
	}

	for _, example := range negativeExamples {
		assert.Nil(t, ParseEncryptedString(example))
	}
}

func TestEncryptedStringDecryptNegative(t *testing.T) {
	id := uuid.Must(uuid.NewV4()).String()

	// short key
	_, err := NewEncryptedString(id, []byte("data"), "key-id", "short_key")
	assert.Error(t, err)

	// not base64
	_, err = NewEncryptedString(id, []byte("data"), "key-id", "!!!")
	assert.Error(t, err)

	es, err := NewEncryptedString(id, []byte("data"), "key-id", "pwFoiPyybQMqNmYVN0gUnpbfpGQV2sDv9vp0ZAxi_Y4")
	assert.NoError(t, err)

	dec := ParseEncryptedString(es.String())
	assert.NotNil(t, dec)

	_, err = dec.Decrypt(id, map[string]string{
		// empty map
	})
	assert.Error(t, err)

	// short key
	_, err = dec.Decrypt(id, map[string]string{
		"key-id": "AQAB",
	})
	assert.Error(t, err)

	// key not base64
	_, err = dec.Decrypt(id, map[string]string{
		"key-id": "!!!",
	})
	assert.Error(t, err)

	// bad key
	_, err = dec.Decrypt(id, map[string]string{
		"key-id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	})
	assert.Error(t, err)

	// bad tag for AEAD failure
	dec.Data[len(dec.Data)-1] += 1

	_, err = dec.Decrypt(id, map[string]string{
		"key-id": "pwFoiPyybQMqNmYVN0gUnpbfpGQV2sDv9vp0ZAxi_Y4",
	})
	assert.Error(t, err)
}

func TestSecureToken(t *testing.T) {
	assert.Equal(t, len(SecureAlphanumeric(22)), 22)
}

func TestVerifySIWS(t *testing.T) {
    pub, priv, err := ed25519.GenerateKey(nil)
    if err != nil {
        t.Fatalf("Failed to generate keypair: %v", err)
    }
    
    now := time.Now().UTC()
    issuedAt := now.Add(-5 * time.Minute)
    expiresAt := now.Add(55 * time.Minute)

    // Base test message
    validMessage := fmt.Sprintf(`example.com wants you to sign in with your Solana account:
%s

I accept the ServiceOrg Terms of Service

URI: https://example.com/login
Version: 1
Chain ID: solana:mainnet
Nonce: 8lb3dW3F
Issued At: %s
Expiration Time: %s
Resources:
- https://example.com/profile
- https://example.com/settings`,
        base58.Encode(pub),
        issuedAt.Format(time.RFC3339),
        expiresAt.Format(time.RFC3339))

    parsedMsg, err := siws.ParseSIWSMessage(validMessage)
    if err != nil {
        t.Fatalf("Failed to parse valid message: %v", err)
    }

    validSignature := ed25519.Sign(priv, []byte(validMessage))

    // Helper function to create a valid base message
    createBaseMsg := func() *siws.SIWSMessage {
        return &siws.SIWSMessage{
            Domain:  "example.com",
            Address: base58.Encode(pub),
            Version: "1",
            URI:     "https://example.com/login",
            ChainID: "solana:mainnet",
            Nonce:   "8lb3dW3F",
        }
    }

    params := siws.SIWSVerificationParams{
        ExpectedDomain: "example.com",
        CheckTime:      true,
        TimeDuration:  time.Hour,
    }

    testCases := []struct {
        name        string
        message     string
        signature   []byte
        msg         *siws.SIWSMessage
        params      siws.SIWSVerificationParams
        expectedErr string
    }{
        {
            name:        "valid message",
            message:     validMessage,
            signature:   validSignature,
            msg:         parsedMsg,
            params:      params,
            expectedErr: "",
        },
        {
            name:        "empty message",
            message:     "",
            signature:   validSignature,
            msg:         parsedMsg,
            params:      params,
            expectedErr: siws.ErrEmptyRawMessage.Message,
        },
        {
            name:        "empty signature",
            message:     validMessage,
            signature:   []byte{},
            msg:         parsedMsg,
            params:      params,
            expectedErr: siws.ErrEmptySignature.Message,
        },
        {
            name:        "nil message struct",
            message:     validMessage,
            signature:   validSignature,
            msg:         nil,
            params:      params,
            expectedErr: siws.ErrNilMessage.Message,
        },
        {
            name:      "invalid address characters",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                // Create a 32-character address with invalid characters
                msg.Address = "Invalid@Address!123" + strings.Repeat("1", 19)
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrInvalidPubKeySize.Message,
        },
        {
            name:      "address too short",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.Address = "abc123"
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrInvalidPubKeySize.Message,
        },
        {
            name:      "invalid version",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.Version = "2"
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrInvalidVersion.Message,
        },
        {
            name:      "invalid chain ID",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.ChainID = "invalid-chain"
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrInvalidChainID.Message,
        },
        {
            name:      "short nonce",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.Nonce = "abc123"
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrNonceTooShort.Message,
        },
        
        {
            name:      "invalid URI format",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.URI = "://invalid-uri-format"  // Invalid URI scheme
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrInvalidURI.Message,
        },
        {
            name:      "invalid resource URI",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.Resources = []string{"://invalid-resource-uri"}  // Invalid URI scheme
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrInvalidResourceURI.Message,
        },
        {
            name:      "future timestamp",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.IssuedAt = now.Add(10 * time.Minute)
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrFutureMessage.Message,
        },
        {
            name:      "expired message",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.IssuedAt = now.Add(-2 * time.Hour)
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrMessageExpired.Message,
        },
        {
            name:      "not yet valid",
            message:   validMessage,
            signature: validSignature,
            msg: func() *siws.SIWSMessage {
                msg := createBaseMsg()
                msg.NotBefore = now.Add(1 * time.Hour)
                return msg
            }(),
            params:      params,
            expectedErr: siws.ErrNotYetValid.Message,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            err := VerifySIWS(tc.message, tc.signature, tc.msg, tc.params)
            if tc.expectedErr == "" {
                if err != nil {
                    t.Errorf("expected success, got error: %v", err)
                }
            } else {
                if err == nil {
                    t.Errorf("expected error containing %q, got nil", tc.expectedErr)
                } else if !strings.Contains(err.Error(), tc.expectedErr) {
                    t.Errorf("expected error containing %q, got %q", tc.expectedErr, err.Error())
                }
            }
        })
    }
}