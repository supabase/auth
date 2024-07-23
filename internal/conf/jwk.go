package conf

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JwtKeysDecoder map[string]JwkInfo

type JwkInfo struct {
	PublicKey  jwk.Key `json:"public_key"`
	PrivateKey jwk.Key `json:"private_key"`
}

// KeyInfo is used to store the initial config of the keys
// The private key should be in DER format and base64 encoded
type KeyInfo struct {
	Type       string `json:"type"`
	PrivateKey string `json:"private_key"`
	InUse      bool   `json:"in_use"`
}

// Decode implements the Decoder interface
// which transforms the keys stored as der binary strings into jwks
func (j *JwtKeysDecoder) Decode(value string) error {
	data := map[string]KeyInfo{}
	if err := json.Unmarshal([]byte(value), &data); err != nil {
		return err
	}

	config := JwtKeysDecoder{}
	for kid, key := range data {
		// all private keys should be stored as der binary strings in base64
		derBytes, err := base64.StdEncoding.DecodeString(key.PrivateKey)
		if err != nil {
			return err
		}

		var privKey any
		if key.Type == "hmac" {
			privKey = derBytes
		} else {
			// assume key is asymmetric
			privKey, err = x509.ParsePKCS8PrivateKey(derBytes)
			if err != nil {
				return err
			}
		}
		alg := getAlg(privKey)
		if alg == "" {
			return fmt.Errorf("unsupported key alg: %v", kid)
		}

		privJwk, err := jwk.FromRaw(privKey)
		if err != nil {
			return err
		}
		// Set kid, alg and use claims for private key
		if err := privJwk.Set(jwk.KeyIDKey, kid); err != nil {
			return err
		}
		if err := privJwk.Set(jwk.AlgorithmKey, alg); err != nil {
			return err
		}

		switch key.InUse {
		case true:
			// only the key that's in use should be used for encryption
			if err := privJwk.Set(jwk.KeyUsageKey, "enc"); err != nil {
				return err
			}
		default:
			if err := privJwk.Set(jwk.KeyUsageKey, "sig"); err != nil {
				return err
			}
		}

		pubJwk, err := jwk.PublicKeyOf(privJwk)
		if err != nil {
			return err
		}

		// public keys are always used for signature verification only
		if err := pubJwk.Set(jwk.KeyUsageKey, "sig"); err != nil {
			return err
		}

		config[kid] = JwkInfo{
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
		if err := key.PublicKey.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func getAlg(key any) string {
	var alg string
	switch p := key.(type) {
	case []byte:
		alg = "HS256"
	case *ecdsa.PrivateKey:
		switch p.Curve.Params().Name {
		case "P-256":
			alg = "ES256"
		case "P-384":
			alg = "ES384"
		case "P-521":
			alg = "ES512"
		}
	case *rsa.PrivateKey:
		switch p.N.BitLen() {
		case 2048:
			alg = "RS256"
		case 4096:
			alg = "RS512"
		}
	case *ed25519.PrivateKey:
		// Ed25519 is still experimental based on https://github.com/lestrrat-go/jwx/tree/develop/v2/jwk#supported-key-types
		alg = "EdDSA"
	default:
		return ""
	}
	return alg
}
