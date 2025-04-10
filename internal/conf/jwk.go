package conf

import (
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JwtKeysDecoder map[string]JwkInfo

type JwkInfo struct {
	PublicKey  jwk.Key `json:"public_key"`
	PrivateKey jwk.Key `json:"private_key"`
}

// Decode implements the Decoder interface
func (j *JwtKeysDecoder) Decode(value string) error {
	data := make([]json.RawMessage, 0)
	if err := json.Unmarshal([]byte(value), &data); err != nil {
		return err
	}

	config := JwtKeysDecoder{}
	for _, key := range data {
		if err := j.decodeKey(config, key); err != nil {
			return err
		}
	}

	*j = config
	return nil
}

func (j *JwtKeysDecoder) decodeKey(config JwtKeysDecoder, key []byte) error {
	privJwk, err := jwk.ParseKey(key)
	if err != nil {
		return err
	}
	return j.decodePrivateKey(config, privJwk)
}

func (j *JwtKeysDecoder) decodePrivateKey(
	config JwtKeysDecoder,
	privJwk jwk.Key,
) error {
	pubJwk, err := jwk.PublicKeyOf(privJwk)
	if err != nil {
		return err
	}
	return j.decodePublicKey(config, privJwk, pubJwk)
}

func (j *JwtKeysDecoder) decodePublicKey(
	config JwtKeysDecoder,
	privJwk jwk.Key,
	pubJwk jwk.Key,
) error {
	// all public keys should have the the use claim set to 'sig
	if err := pubJwk.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return err
	}

	// all public keys should only have 'verify' set as the key_ops
	if err := pubJwk.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpVerify}); err != nil {
		return err
	}

	config[pubJwk.KeyID()] = JwkInfo{
		PublicKey:  pubJwk,
		PrivateKey: privJwk,
	}
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
	// Note that depending on the underlying key type, use of this method requires
	// that multiple fields in the key are properly populated. For example, an EC
	// key's "x", "y" fields cannot be validated unless the "crv" field is populated first.
	signingKeys := []jwk.Key{}
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

		for _, op := range key.PrivateKey.KeyOps() {
			if op == jwk.KeyOpSign {
				signingKeys = append(signingKeys, key.PrivateKey)
				break
			}
		}
	}

	switch {
	case len(signingKeys) == 0:
		return fmt.Errorf("no signing key detected")
	case len(signingKeys) > 1:
		return fmt.Errorf("multiple signing keys detected, only 1 signing key is supported")
	}

	return nil
}

func GetSigningJwk(config *JWTConfiguration) (jwk.Key, error) {
	for _, key := range config.Keys {
		for _, op := range key.PrivateKey.KeyOps() {
			// the private JWK with key_ops "sign" should be used as the signing key
			if op == jwk.KeyOpSign {
				return key.PrivateKey, nil
			}
		}
	}
	return nil, fmt.Errorf("no signing key found")
}

func GetSigningKey(k jwk.Key) (any, error) {
	var key any
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
