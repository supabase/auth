package conf

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JwtKeysDecoder map[string]JwkInfo

type JwkInfo struct {
	PublicKey  jwk.Key `json:"public_key"`
	PrivateKey jwk.Key `json:"private_key"`
}

// Decode implements the Decoder interface
// which transforms the keys stored as der binary strings into jwks
func (j *JwtKeysDecoder) Decode(value string) error {
	data := make([]json.RawMessage, 0)
	if err := json.Unmarshal([]byte(value), &data); err != nil {
		return err
	}

	config := JwtKeysDecoder{}
	for _, key := range data {
		privJwk, err := jwk.ParseKey(key)
		if err != nil {
			return err
		}
		pubJwk, err := jwk.PublicKeyOf(privJwk)
		if err != nil {
			return err
		}

		// ensures that all public keys only have 'verify' as the key_ops
		if err := pubJwk.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpVerify}); err != nil {
			return err
		}

		config[pubJwk.KeyID()] = JwkInfo{
			PublicKey:  pubJwk,
			PrivateKey: privJwk,
		}
	}
	*j = config
	return nil
}

func (j *JwtKeysDecoder) Validate() error {
	// Validate performs _minimal_ checks if the data stored in the key are valid.
	// By minimal, we mean that it does not check if the key is valid for use in
	// cryptographic operations. For example, it does not check if an RSA key's
	// `e` field is a valid exponent, or if the `n` field is a valid modulus.
	// Instead, it checks for things such as the _presence_ of some required fields,
	// or if certain keys' values are of particular length.
	//
	// Note that depending on th underlying key type, use of this method requires
	// that multiple fields in the key are properly populated. For example, an EC
	// key's "x", "y" fields cannot be validated unless the "crv" field is populated first.
	for _, key := range *j {
		if err := key.PrivateKey.Validate(); err != nil {
			return err
		}
		// symmetric keys don't have public keys
		if key.PublicKey != nil {
			if err := key.PublicKey.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

func GetSigningJwk(config *JWTConfiguration) (jwk.Key, error) {
	for _, key := range config.Keys {
		for _, op := range key.PrivateKey.KeyOps() {
			if op == jwk.KeyOpSign {
				return key.PrivateKey, nil
			}
		}
	}
	return nil, fmt.Errorf("no signing key found")
}

func GetSigningKey(k jwk.Key) (any, error) {
	var key any
	switch k.KeyType() {
	case jwa.OctetSeq:
		key = []byte{}
	case jwa.EC:
		key = ecdh.PrivateKey{}
	case jwa.RSA:
		key = rsa.PrivateKey{}
	case jwa.OKP:
		// OKP is used for EdDSA keys
		key = ed25519.PrivateKey{}
	case jwa.InvalidKeyType:
		return nil, jwt.ErrInvalidKeyType
	}
	if err := k.Raw(&key); err != nil {
		return nil, err
	}
	return key, nil
}

func GetSigningAlg(k jwk.Key) jwt.SigningMethod {
	if k == nil {
		return jwt.SigningMethodHS256
	}

	switch (k).Algorithm().String() {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES512":
		return jwt.SigningMethodES512
	case "EdDSA":
		return jwt.SigningMethodEdDSA
	}

	// return HS256 to preserve existing behaviour
	return jwt.SigningMethodHS256
}

func FindPublicKeyByKid(kid string, config *JWTConfiguration) (any, error) {
	if k, ok := config.Keys[kid]; ok {
		key, err := GetSigningKey(k.PublicKey)
		if err != nil {
			return nil, err
		}
		return key, nil
	}
	if kid == config.KeyID {
		return []byte(config.Secret), nil
	}
	return nil, fmt.Errorf("invalid kid: %s", kid)
}
