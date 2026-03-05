package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// virtualAuthenticator simulates a WebAuthn authenticator for testing.
// It generates real EC P-256 key pairs and constructs valid attestation
// responses that pass go-webauthn library verification.
type virtualAuthenticator struct {
	rpID   string
	origin string
}

// virtualCredentialResponse is the result of creating a credential with the virtual authenticator.
type virtualCredentialResponse struct {
	// JSON is the raw JSON of the CredentialCreationResponse, ready to be sent as credential_response.
	JSON json.RawMessage
}

// createCredential builds a valid WebAuthn CredentialCreationResponse for the given
// registration options. It generates a fresh EC P-256 key pair and uses "none" attestation.
func (va *virtualAuthenticator) createCredential(options *protocol.CredentialCreation) (*virtualCredentialResponse, error) {
	challenge := options.Response.Challenge

	// Generate a fresh P-256 key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		return nil, err
	}

	clientDataJSON, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin":    va.origin,
	})
	if err != nil {
		return nil, err
	}

	authData, err := va.buildAuthData(credentialID, privKey)
	if err != nil {
		return nil, err
	}

	attestationObject, err := va.buildAttestationObject(authData)
	if err != nil {
		return nil, err
	}

	resp := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(credentialID),
				Type: "public-key",
			},
			RawID: credentialID,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{
				ClientDataJSON: clientDataJSON,
			},
			AttestationObject: attestationObject,
			Transports:        []string{"internal"},
		},
	}

	respJSON, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	return &virtualCredentialResponse{JSON: respJSON}, nil
}

// buildAuthData constructs the raw authenticator data bytes.
// Layout: rpIdHash (32) || flags (1) || signCount (4) || attestedCredentialData
func (va *virtualAuthenticator) buildAuthData(credentialID []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {
	rpIDHash := sha256.Sum256([]byte(va.rpID))

	// flags: UP (bit 0) | AT (bit 6) = 0x41
	flags := byte(0x41)

	coseKey, err := marshalCOSEPublicKey(privKey)
	if err != nil {
		return nil, err
	}

	// attestedCredentialData: aaguid (16) || credIdLen (2) || credId || coseKey
	aaguid := make([]byte, 16) // all zeros
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID))) //#nosec G115 — we control the length and ensure it's within bounds

	var authData []byte
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, 0, 0, 0, 0) // signCount = 0
	authData = append(authData, aaguid...)
	authData = append(authData, credIDLen...)
	authData = append(authData, credentialID...)
	authData = append(authData, coseKey...)

	return authData, nil
}

// buildAttestationObject builds a CBOR-encoded attestation object with "none" format.
func (va *virtualAuthenticator) buildAttestationObject(authData []byte) ([]byte, error) {
	attObj := map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	}
	return cbor.Marshal(attObj)
}

// marshalCOSEPublicKey encodes an ECDSA P-256 public key in COSE_Key format (CBOR).
func marshalCOSEPublicKey(privKey *ecdsa.PrivateKey) ([]byte, error) {
	ecdhKey, err := privKey.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	// Bytes() returns the uncompressed point: 0x04 || x (32 bytes) || y (32 bytes)
	uncompressed := ecdhKey.Bytes()
	x := uncompressed[1:33]
	y := uncompressed[33:65]

	// COSE_Key with integer keys:
	//   1 (kty): 2 (EC2)
	//   3 (alg): -7 (ES256)
	//  -1 (crv): 1 (P-256)
	//  -2 (x):   x coordinate
	//  -3 (y):   y coordinate
	coseKey := map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: x,
		-3: y,
	}
	return cbor.Marshal(coseKey)
}
