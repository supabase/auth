package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	siws "github.com/supabase/auth/internal/utilities/solana"
)

const (
	// Chain identifiers
	chainSolanaMainnet = "solana:mainnet"

	// Grant type
	grantTypeWeb3 = "web3"

	// Error responses
	errorInvalidGrant = "invalid_grant"

	// Test values
	defaultTestURI = "https://example.com"

	// Endpoints
	tokenEndpoint = "/token"
)

type Web3TestSuite struct {
	suite.Suite
	API          *API
	Config       *conf.GlobalConfiguration
	pubKey       ed25519.PublicKey
	privKey      ed25519.PrivateKey
	pubKeyBase58 string

	// Test configuration
	testURI string
}

type TokenRequest struct {
	GrantType string `json:"grant_type"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Address   string `json:"address"`
	Chain     string `json:"chain"`
}

func TestWeb3(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &Web3TestSuite{
		API:     api,
		Config:  config,
		testURI: defaultTestURI,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *Web3TestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	ts.Config.DisableSignup = false
	ts.Config.Mailer.AllowUnverifiedEmailSignIns = true

	// Generate test keys for Solana
	var err error
	ts.pubKey, ts.privKey, err = ed25519.GenerateKey(rand.Reader)
	ts.Require().NoError(err)
	ts.pubKeyBase58 = base58.Encode(ts.pubKey)
}

func newSIWSRequest(t *testing.T, grantType, message, signature, address, chain string) *http.Request {
	tokenRequest := TokenRequest{
		Message:   message,
		Signature: signature,
		Address:   address,
		Chain:     chain,
	}
	jsonBody, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("%s?grant_type=%s", tokenEndpoint, grantType), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (ts *Web3TestSuite) generateSIWSMessageAndSignature(nonce string) (string, string) {
	msg := siws.SIWSMessage{
		Domain:    ts.Config.External.Web3.Domain,
		Address:   ts.pubKeyBase58,
		Statement: ts.Config.External.Web3.Statement,
		URI:       ts.testURI,
		Version:   ts.Config.External.Web3.Version,
		Nonce:     nonce,
		IssuedAt:  time.Now().UTC(),
	}
	rawMessage := siws.ConstructMessage(msg)
	signature := ed25519.Sign(ts.privKey, []byte(rawMessage))
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	return rawMessage, signatureBase64
}

func (ts *Web3TestSuite) assertErrorResponse(w *httptest.ResponseRecorder, expectedCode int, expectedError string) {
	ts.Require().Equal(expectedCode, w.Code)
	var errorResponse map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&errorResponse)
	ts.Require().NoError(err)
	ts.Require().Equal(expectedError, errorResponse["error"])
}

func (ts *Web3TestSuite) TestSignupWeb3_InvalidSignature() {
	nonce := crypto.SecureAlphanumeric(12)

	rawMessage, _ := ts.generateSIWSMessageAndSignature(nonce)

	invalidSignature := base64.StdEncoding.EncodeToString(make([]byte, 64))

	req := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, invalidSignature, ts.pubKeyBase58, chainSolanaMainnet)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.assertErrorResponse(w, http.StatusBadRequest, errorInvalidGrant)
}

func (ts *Web3TestSuite) TestSignupWeb3_MalformedMessage() {
	nonce := crypto.SecureAlphanumeric(12)

	malformedMessage := fmt.Sprintf(`{
		"domain": "%s",
		"uri": "%s",
		"version": "1",
		"nonce": "%s"
	}`, ts.Config.External.Web3.Domain, ts.testURI, nonce)

	_, signatureBase64 := ts.generateSIWSMessageAndSignature(nonce)

	req := newSIWSRequest(ts.T(), grantTypeWeb3, malformedMessage, signatureBase64, ts.pubKeyBase58, chainSolanaMainnet)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.assertErrorResponse(w, http.StatusBadRequest, errorInvalidGrant)
}

func (ts *Web3TestSuite) TestSignupWeb3_InvalidChain() {
	nonce := crypto.SecureAlphanumeric(12)
	rawMessage, signatureBase64 := ts.generateSIWSMessageAndSignature(nonce)

	invalidChain := "invalid-chain"
	req := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, signatureBase64, ts.pubKeyBase58, invalidChain)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.assertErrorResponse(w, http.StatusBadRequest, errorInvalidGrant)
}
