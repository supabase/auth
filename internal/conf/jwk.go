package conf

import (
	"encoding/base64"
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
// which transforms the keys stored as der binary strings into jwks
func (j *JwtKeysDecoder) Decode(value string) error {
	data := make([]map[string]interface{}, 0)
	if err := json.Unmarshal([]byte(value), &data); err != nil {
		return err
	}

	config := JwtKeysDecoder{}
	for _, key := range data {
		bytes, err := json.Marshal(key)
		if err != nil {
			return err
		}
		privJwk, err := jwk.ParseKey(bytes)
		if err != nil {
			return err
		}
		pubJwk, err := jwk.PublicKeyOf(privJwk)
		if err != nil {
			return err
		}

		// all public keys will be used for signature verification
		if pubJwk.KeyUsage() == "enc" {
			if err := pubJwk.Set(jwk.KeyUsageKey, "sig"); err != nil {
				return err
			}
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

func GetSigningJwk(config *JWTConfiguration) (*jwk.Key, error) {
	if config.Keys == nil {
		symmetricJwk, err := getSymmetricKey(config)
		if err != nil {
			return nil, err
		}
		return symmetricJwk, nil
	}
	for _, key := range config.Keys {
		if key.PrivateKey.KeyUsage() == "enc" {
			return &key.PrivateKey, nil
		}
	}
	// return symmetric secret anyway to preserve existing behavior
	symmetricJwk, err := getSymmetricKey(config)
	if err != nil {
		return nil, err
	}
	return symmetricJwk, nil
}

func GetSigningKey(k *jwk.Key) (any, error) {
	switch (*k).KeyType() {
	case "oct":
		var symmetricKey []byte
		if err := (*k).Raw(symmetricKey); err != nil {
			return nil, err
		}
		return symmetricKey, nil
	default:
		var key interface{}
		if err := (*k).Raw(&key); err != nil {
			return nil, err
		}
		return key, nil
	}
}

func GetSigningAlg(k *jwk.Key) jwt.SigningMethod {
	if k == nil {
		return jwt.SigningMethodHS256
	}

	switch (*k).Algorithm().String() {
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

func getSymmetricKey(config *JWTConfiguration) (*jwk.Key, error) {
	if config.Secret != "" {
		bytes, err := base64.StdEncoding.DecodeString(config.Secret)
		if err != nil {
			bytes = []byte(config.Secret)
		}
		privKey, err := jwk.FromRaw(bytes)
		if err != nil {
			return nil, err
		}
		if config.KeyID != "" {
			if err := privKey.Set(jwk.KeyIDKey, config.KeyID); err != nil {
				return nil, err
			}
		}
		if privKey.Algorithm().String() == "" {
			if err := privKey.Set(jwk.AlgorithmKey, "HS256"); err != nil {
				return nil, err
			}
		}
		if privKey.KeyUsage() == "" {
			if err := privKey.Set(jwk.KeyUsageKey, "enc"); err != nil {
				return nil, err
			}
		}
		return &privKey, nil
	}
	return nil, fmt.Errorf("missing symmetric key")
}
