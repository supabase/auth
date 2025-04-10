package crypto

import (
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
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
