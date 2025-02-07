package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/supabase/auth/internal/conf"
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

func (ts *ExternalTestSuite) TestSignupExternalSIWS() {
	SIWSTestSignupSetup(ts)
	ts.Config.DisableSignup = false

	// Generate test keys for Solana
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	ts.Require().NoError(err)
	pubKeyBase58 := base58.Encode(pubKey)

	nonce, err := siws.GenerateNonce()
	ts.Require().NoError(err)

	// Create test message
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
	signature := ed25519.Sign(privKey, []byte(rawMessage))
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	// Create JSON request body
	tokenRequest := TokenRequest{
		GrantType: "web3",
		Message:   rawMessage,
		Signature: signatureBase64,
		Address:   pubKeyBase58,
		Chain:     "solana:mainnet",
	}

	jsonBody, err := json.Marshal(tokenRequest)
	ts.Require().NoError(err)

	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	ts.Require().Equal(http.StatusOK, w.Code)

	var token AccessTokenResponse
	ts.Require().NoError(json.NewDecoder(w.Body).Decode(&token))

	ts.Require().NotEmpty(token.Token)
	ts.Require().NotEmpty(token.RefreshToken)
	ts.Require().Equal("bearer", token.TokenType)
	ts.Require().NotNil(token.User)
}
