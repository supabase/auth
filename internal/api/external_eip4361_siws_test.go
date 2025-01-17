package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/supabase/auth/internal/conf"
	siws "github.com/supabase/auth/internal/utilities/siws"
)

const (
	siwsValidUser   string = `{"address":"12345abcde","chain":"solana:mainnet"}`
	siwsWrongChain  string = `{"address":"12345abcde","chain":"ethereum:1"}`
	siwsInvalidUser string = `{"address":"","chain":"solana:mainnet"}`
)

func SIWSTestSignupSetup(ts *ExternalTestSuite) {
	ts.Config.External.EIP4361 = conf.EIP4361Configuration{
		Enabled:         true,
		Domain:          "test.example.com",
		Statement:       "Sign in with your Solana account",
		Version:         "1",
		Timeout:         5 * time.Minute,
		SupportedChains: "solana:mainnet",
		DefaultChain:    "solana:mainnet",
	}
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
		Domain:    ts.Config.External.EIP4361.Domain,
		Address:   pubKeyBase58,
		Statement: ts.Config.External.EIP4361.Statement,
		URI:       "https://example.com",
		Version:   ts.Config.External.EIP4361.Version,
		Nonce:     nonce,
		IssuedAt:  time.Now().UTC(),
	}

	rawMessage := siws.ConstructMessage(msg)
	signature := ed25519.Sign(privKey, []byte(rawMessage))
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	formData := url.Values{}
	formData.Set("grant_type", "eip4361")
	formData.Set("message", rawMessage)
	formData.Set("signature", signatureBase64)
	formData.Set("address", pubKeyBase58)
	formData.Set("chain", "solana:mainnet")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
