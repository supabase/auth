package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	siws "github.com/supabase/auth/internal/utilities/solana"
)

const (
	siwsValidUser   string = `{"address":"12345abcde","chain":"solana:mainnet"}`
	siwsWrongChain  string = `{"address":"12345abcde","chain":"ethereum:1"}`
	siwsInvalidUser string = `{"address":"","chain":"solana:mainnet"}`
)

func SIWSTestSignupSetup(ts *ExternalTestSuite) {
	ts.Config.External.Web3 = conf.Web3Configuration{
		Enabled:         true,
		Domain:          "test.example.com",
		Statement:       "Sign in with your Solana account",
		Version:         "1",
		Timeout:         5 * time.Minute,
		SupportedChains: "solana:mainnet",
		DefaultChain:    "solana:mainnet",
	}
}

type TokenRequest struct {
	GrantType string `json:"grant_type"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Address   string `json:"address"`
	Chain     string `json:"chain"`
}

// newNonceRequest creates a new nonce request for testing
func newNonceRequest(t *testing.T, address string) *http.Request {
	body := map[string]string{"address": address}
	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/nonce", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// newSIWSRequest creates a new SIWS token request for testing
func newSIWSRequest(t *testing.T, grantType, message, signature, address, chain string) *http.Request {
	tokenRequest := TokenRequest{
		GrantType: grantType,
		Message:   message,
		Signature: signature,
		Address:   address,
		Chain:     chain,
	}
	jsonBody, err := json.Marshal(tokenRequest)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (ts *ExternalTestSuite) TestSignupExternalSIWS() {
	SIWSTestSignupSetup(ts)
	ts.Config.DisableSignup = false

	// Generate test keys for Solana
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	ts.Require().NoError(err)
	pubKeyBase58 := base58.Encode(pubKey)

	// --- 1. Get a Nonce ---
	nonceReq := newNonceRequest(ts.T(), pubKeyBase58)
	nonceW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(nonceW, nonceReq)
	ts.Require().Equal(http.StatusOK, nonceW.Code)

	var nonceResp map[string]interface{}
	ts.Require().NoError(json.NewDecoder(nonceW.Body).Decode(&nonceResp))
	nonce, ok := nonceResp["nonce"].(string)
	ts.Require().True(ok)
	ts.Require().NotEmpty(nonce)
	expiresAtStr, ok := nonceResp["expiresAt"].(string)
	ts.Require().True(ok)
	_, err = time.Parse(time.RFC3339, expiresAtStr) // Parse but don't store
	ts.Require().NoError(err)

	// --- 2. Construct SIWS Message ---
	msg := siws.SIWSMessage{
		Domain:    ts.Config.External.Web3.Domain,
		Address:   pubKeyBase58,
		Statement: ts.Config.External.Web3.Statement,
		URI:       "https://example.com",
		Version:   ts.Config.External.Web3.Version,
		Nonce:     nonce,
		IssuedAt:  time.Now().UTC(),
	}
	rawMessage := siws.ConstructMessage(msg)

	// --- 3. Sign the Message ---
	signature := ed25519.Sign(privKey, []byte(rawMessage))
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// --- 4. Successful Login ---
	req := newSIWSRequest(ts.T(), "web3", rawMessage, signatureBase64, pubKeyBase58, "solana:mainnet")
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusOK, w.Code)

	var token AccessTokenResponse
	ts.Require().NoError(json.NewDecoder(w.Body).Decode(&token))
	ts.Require().NotEmpty(token.Token)
	ts.Require().NotEmpty(token.RefreshToken)
	ts.Require().Equal("bearer", token.TokenType)
	ts.Require().NotNil(token.User)

	// Find the stored nonce
	db := ts.API.db
	storedNonce, err := FindStoredNonceByAddressAndNonce(db, pubKeyBase58, nonce)
	ts.Require().NoError(err)
	ts.Require().NotNil(storedNonce)
	ts.Require().True(storedNonce.Used) // Verify it's marked as used

	// --- 5. Replay Attack (Same Nonce) ---
	replayReq := newSIWSRequest(ts.T(), "web3", rawMessage, signatureBase64, pubKeyBase58, "solana:mainnet")
	replayW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(replayW, replayReq)
	ts.Require().Equal(http.StatusBadRequest, replayW.Code) // Expect failure due to replay
	ts.Require().Contains(replayW.Body.String(), "invalid_grant")

	// --- 6. Expired Nonce ---
	// Create a new expired nonce directly in database
	expiredNonce := &StoredNonce{
		ID:        uuid.Must(uuid.NewV4()),
		Address:   pubKeyBase58,
		Nonce:     "expired-nonce",
		CreatedAt: time.Now().Add(-2 * ts.Config.External.Web3.Timeout), // Make it expired
		ExpiresAt: time.Now().Add(-1 * ts.Config.External.Web3.Timeout), // Make it expired
		Used:      false,
	}
	err = ts.API.db.Create(expiredNonce)
	ts.Require().NoError(err)

	expiredMsg := msg
	expiredMsg.Nonce = "expired-nonce"
	expiredRawMessage := siws.ConstructMessage(expiredMsg)
	expiredSignature := ed25519.Sign(privKey, []byte(expiredRawMessage))
	expiredSignatureBase64 := base64.StdEncoding.EncodeToString(expiredSignature)

	expiredReq := newSIWSRequest(ts.T(), "web3", expiredRawMessage, expiredSignatureBase64, pubKeyBase58, "solana:mainnet")
	expiredW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(expiredW, expiredReq)
	ts.Require().Equal(http.StatusBadRequest, expiredW.Code) // Expect failure - expired
	ts.Require().Contains(expiredW.Body.String(), "invalid_grant")

	// --- 7.  Invalid/Tampered Nonce ---
	tamperedMsg := msg
	tamperedMsg.Nonce = "invalid-nonce" // An invalid nonce
	tamperedRawMessage := siws.ConstructMessage(tamperedMsg)
	tamperedSignature := ed25519.Sign(privKey, []byte(tamperedRawMessage))
	tamperedSignatureBase64 := base64.StdEncoding.EncodeToString(tamperedSignature)

	tamperedReq := newSIWSRequest(ts.T(), "web3", tamperedRawMessage, tamperedSignatureBase64, pubKeyBase58, "solana:mainnet")
	tamperedW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(tamperedW, tamperedReq)
	ts.Require().Equal(http.StatusBadRequest, tamperedW.Code)
	ts.Require().Contains(tamperedW.Body.String(), "invalid_grant")

	// --- 8. Used Nonce, from a different address (should still fail)---
	// First, generate a nonce for a *different* address
	pubKey2, privKey2, err := ed25519.GenerateKey(rand.Reader)
	ts.Require().NoError(err)
	pubKeyBase58_2 := base58.Encode(pubKey2)

	nonceReq2 := newNonceRequest(ts.T(), pubKeyBase58_2)
	nonceW2 := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(nonceW2, nonceReq2)
	ts.Require().Equal(http.StatusOK, nonceW2.Code)

	var nonceResp2 map[string]interface{}
	ts.Require().NoError(json.NewDecoder(nonceW2.Body).Decode(&nonceResp2))
	nonce2, ok := nonceResp2["nonce"].(string)
	ts.Require().True(ok)

	// Use that nonce to successfully authenticate the *second* user.
	msg2 := siws.SIWSMessage{
		Domain:    ts.Config.External.Web3.Domain,
		Address:   pubKeyBase58_2,
		Statement: ts.Config.External.Web3.Statement,
		URI:       "https://example.com",
		Version:   ts.Config.External.Web3.Version,
		Nonce:     nonce2,
		IssuedAt:  time.Now().UTC(),
	}

	rawMessage2 := siws.ConstructMessage(msg2)
	signature2 := ed25519.Sign(privKey2, []byte(rawMessage2))
	signatureBase64_2 := base64.StdEncoding.EncodeToString(signature2)

	req2 := newSIWSRequest(ts.T(), "web3", rawMessage2, signatureBase64_2, pubKeyBase58_2, "solana:mainnet")
	w2 := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w2, req2)
	ts.Require().Equal(http.StatusOK, w2.Code)

	// Now try to use nonce2 with the *original* user/address (pubKeyBase58).  This should fail.
	msg3 := siws.SIWSMessage{
		Domain:    ts.Config.External.Web3.Domain,
		Address:   pubKeyBase58, // Original address
		Statement: ts.Config.External.Web3.Statement,
		URI:       "https://example.com",
		Version:   ts.Config.External.Web3.Version,
		Nonce:     nonce2,       // Nonce from the *other* user.
		IssuedAt:  time.Now().UTC(),
	}
	rawMessage3 := siws.ConstructMessage(msg3)
	signature3 := ed25519.Sign(privKey, []byte(rawMessage3)) // Sign with original private key
	signatureBase64_3 := base64.StdEncoding.EncodeToString(signature3)

	req3 := newSIWSRequest(ts.T(), "web3", rawMessage3, signatureBase64_3, pubKeyBase58, "solana:mainnet")
	w3 := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w3, req3)
	ts.Require().Equal(http.StatusBadRequest, w3.Code)
	ts.Require().Contains(w3.Body.String(), "invalid_grant") // Nonce mismatch
}

func FindStoredNonceByAddressAndNonce(db *storage.Connection, address, nonce string) (*StoredNonce, error) {
	storedNonce := &StoredNonce{}
	err := db.RawQuery(`
        SELECT * FROM auth.nonces
        WHERE address = ? AND nonce = ?
    `, address, nonce).First(storedNonce)

	if models.IsNotFoundError(err) {
		return nil, nil // Or perhaps a custom NotFound error
	} else if err != nil {
		return nil, err
	}
	return storedNonce, nil
}