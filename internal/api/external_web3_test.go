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
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
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
	
	// Test nonces
	expiredNonceValue = "expired-nonce"
	invalidNonceValue = "invalid-nonce"
	testNonceValue   = "test-nonce"
	
	// Endpoints
	nonceEndpoint = "/nonce"
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

func newNonceRequest(t *testing.T, address string) *http.Request {
	body := map[string]string{"address": address}
	jsonBody, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, nonceEndpoint, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	return req
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

func (ts *Web3TestSuite) assertTokenResponse(w *httptest.ResponseRecorder) AccessTokenResponse {
	ts.Require().Equal(http.StatusOK, w.Code)
	var token AccessTokenResponse
	ts.Require().NoError(json.NewDecoder(w.Body).Decode(&token))
	ts.Require().NotEmpty(token.Token)
	ts.Require().NotEmpty(token.RefreshToken)
	ts.Require().Equal("bearer", token.TokenType)
	ts.Require().NotNil(token.User)
	return token
}

func (ts *Web3TestSuite) assertErrorResponse(w *httptest.ResponseRecorder, expectedCode int, expectedError string) {
	ts.Require().Equal(expectedCode, w.Code)
	var errorResponse map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&errorResponse)
	ts.Require().NoError(err)
	ts.Require().Equal(expectedError, errorResponse["error"])
}

func (ts *Web3TestSuite) TestSignupWeb3_SuccessfulLogin() {
	nonceReq := newNonceRequest(ts.T(), ts.pubKeyBase58)
	nonceW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(nonceW, nonceReq)
	ts.Require().Equal(http.StatusOK, nonceW.Code)

	var nonceResp map[string]interface{}
	ts.Require().NoError(json.NewDecoder(nonceW.Body).Decode(&nonceResp))
	nonce, ok := nonceResp["nonce"].(string)
	ts.Require().True(ok)
	ts.Require().NotEmpty(nonce)

	rawMessage, signatureBase64 := ts.generateSIWSMessageAndSignature(nonce)

	req := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, signatureBase64, ts.pubKeyBase58, chainSolanaMainnet)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.assertTokenResponse(w)

	storedNonce, err := FindStoredNonceByAddressAndNonce(ts.API.db, ts.pubKeyBase58, nonce)
	ts.Require().NoError(err)
	ts.Require().NotNil(storedNonce)
	ts.Require().True(storedNonce.Used)
}

func (ts *Web3TestSuite) TestSignupWeb3_ReplayAttack() {
	nonceReq := newNonceRequest(ts.T(), ts.pubKeyBase58)
	nonceW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(nonceW, nonceReq)
	ts.Require().Equal(http.StatusOK, nonceW.Code)

	var nonceResp map[string]interface{}
	ts.Require().NoError(json.NewDecoder(nonceW.Body).Decode(&nonceResp))
	nonce, _ := nonceResp["nonce"].(string)

	rawMessage, signatureBase64 := ts.generateSIWSMessageAndSignature(nonce)
	req := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, signatureBase64, ts.pubKeyBase58, chainSolanaMainnet)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.assertTokenResponse(w)

	replayReq := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, signatureBase64, ts.pubKeyBase58, chainSolanaMainnet)
	replayW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(replayW, replayReq)
	ts.assertErrorResponse(replayW, http.StatusBadRequest, errorInvalidGrant)
}

func (ts *Web3TestSuite) TestSignupWeb3_ExpiredNonce() {
	expiredNonce := &StoredNonce{
		ID:        uuid.Must(uuid.NewV4()),
		Address:   ts.pubKeyBase58,
		Nonce:     expiredNonceValue,
		CreatedAt: time.Now().Add(-2 * ts.Config.External.Web3.Timeout),
		ExpiresAt: time.Now().Add(-1 * ts.Config.External.Web3.Timeout),
		Used:      false,
	}
	err := ts.API.db.Create(expiredNonce)
	ts.Require().NoError(err)

	rawMessage, signatureBase64 := ts.generateSIWSMessageAndSignature(expiredNonceValue)

	expiredReq := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, signatureBase64, ts.pubKeyBase58, chainSolanaMainnet)
	expiredW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(expiredW, expiredReq)
	ts.assertErrorResponse(expiredW, http.StatusBadRequest, errorInvalidGrant)
}

func (ts *Web3TestSuite) TestSignupWeb3_InvalidNonce() {
	rawMessage, signatureBase64 := ts.generateSIWSMessageAndSignature(invalidNonceValue)

	tamperedReq := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, signatureBase64, ts.pubKeyBase58, chainSolanaMainnet)
	tamperedW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(tamperedW, tamperedReq)
	ts.assertErrorResponse(tamperedW, http.StatusBadRequest, errorInvalidGrant)
}

func (ts *Web3TestSuite) TestSignupWeb3_UsedNonceDifferentAddress() {
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

	msg2 := siws.SIWSMessage{
		Domain:    ts.Config.External.Web3.Domain,
		Address:   pubKeyBase58_2,
		Statement: ts.Config.External.Web3.Statement,
		URI:       ts.testURI,
		Version:   ts.Config.External.Web3.Version,
		Nonce:     nonce2,
		IssuedAt:  time.Now().UTC(),
	}

	rawMessage2 := siws.ConstructMessage(msg2)
	signature2 := ed25519.Sign(privKey2, []byte(rawMessage2))
	signatureBase64_2 := base64.StdEncoding.EncodeToString(signature2)

	req2 := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage2, signatureBase64_2, pubKeyBase58_2, chainSolanaMainnet)
	w2 := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w2, req2)
	ts.assertTokenResponse(w2)

	msg3 := siws.SIWSMessage{
		Domain:    ts.Config.External.Web3.Domain,
		Address:   ts.pubKeyBase58,
		Statement: ts.Config.External.Web3.Statement,
		URI:       ts.testURI,
		Version:   ts.Config.External.Web3.Version,
		Nonce:     nonce2,
		IssuedAt:  time.Now().UTC(),
	}
	rawMessage3 := siws.ConstructMessage(msg3)
	signature3 := ed25519.Sign(ts.privKey, []byte(rawMessage3))
	signatureBase64_3 := base64.StdEncoding.EncodeToString(signature3)

	req3 := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage3, signatureBase64_3, ts.pubKeyBase58, chainSolanaMainnet)
	w3 := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w3, req3)
	ts.assertErrorResponse(w3, http.StatusBadRequest, errorInvalidGrant)
}

func (ts *Web3TestSuite) TestSignupWeb3_InvalidSignature() {
	nonceReq := newNonceRequest(ts.T(), ts.pubKeyBase58)
	nonceW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(nonceW, nonceReq)
	ts.Require().Equal(http.StatusOK, nonceW.Code)

	var nonceResp map[string]interface{}
	ts.Require().NoError(json.NewDecoder(nonceW.Body).Decode(&nonceResp))
	nonce, ok := nonceResp["nonce"].(string)
	ts.Require().True(ok)

	rawMessage, _ := ts.generateSIWSMessageAndSignature(nonce)

	invalidSignature := base64.StdEncoding.EncodeToString(make([]byte, 64))

	req := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, invalidSignature, ts.pubKeyBase58, chainSolanaMainnet)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.assertErrorResponse(w, http.StatusBadRequest, errorInvalidGrant)
}

func (ts *Web3TestSuite) TestSignupWeb3_MalformedMessage() {
	nonceReq := newNonceRequest(ts.T(), ts.pubKeyBase58)
	nonceW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(nonceW, nonceReq)
	nonceResp := map[string]interface{}{}
	_ = json.NewDecoder(nonceW.Body).Decode(&nonceResp)
	nonce, _ := nonceResp["nonce"].(string)

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
	nonceReq := newNonceRequest(ts.T(), ts.pubKeyBase58)
	nonceW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(nonceW, nonceReq)
	ts.Require().Equal(http.StatusOK, nonceW.Code)

	var nonceResp map[string]interface{}
	ts.Require().NoError(json.NewDecoder(nonceW.Body).Decode(&nonceResp))
	nonce, ok := nonceResp["nonce"].(string)
	ts.Require().True(ok)

	rawMessage, signatureBase64 := ts.generateSIWSMessageAndSignature(nonce)

	invalidChain := "invalid-chain"
	req := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, signatureBase64, ts.pubKeyBase58, invalidChain)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.assertErrorResponse(w, http.StatusBadRequest, errorInvalidGrant)
}

func FindStoredNonceByAddressAndNonce(db *storage.Connection, address, nonce string) (*StoredNonce, error) {
	storedNonce := &StoredNonce{}
	err := db.RawQuery(`
        SELECT * FROM auth.nonces
        WHERE address = ? AND nonce = ?
    `, address, nonce).First(storedNonce)

	if models.IsNotFoundError(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return storedNonce, nil
}

func (ts *Web3TestSuite) TestNonceExpiryConstraint() {
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	ts.Require().NoError(err)
	pubKeyBase58 := base58.Encode(pubKey)

	invalidNonce := &StoredNonce{
		ID:        uuid.Must(uuid.NewV4()),
		Address:   pubKeyBase58,
		Nonce:     testNonceValue,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Used:      false,
	}

	err = ts.API.db.Create(invalidNonce)
	ts.Require().Error(err)
	ts.Require().Contains(err.Error(), "nonces_expiry_check")

	validNonce := &StoredNonce{
		ID:        uuid.Must(uuid.NewV4()),
		Address:   pubKeyBase58,
		Nonce:     testNonceValue,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}

	err = ts.API.db.Create(validNonce)
	ts.Require().NoError(err)

	storedNonce, err := FindStoredNonceByAddressAndNonce(ts.API.db, pubKeyBase58, testNonceValue)
	ts.Require().NoError(err)
	ts.Require().NotNil(storedNonce)
	ts.Require().True(storedNonce.ExpiresAt.After(storedNonce.CreatedAt))
}

func (ts *Web3TestSuite) TestSignupWeb3_ConcurrentNonceUsage() {
	nonceReq := newNonceRequest(ts.T(), ts.pubKeyBase58)
	nonceW := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(nonceW, nonceReq)
	ts.Require().Equal(http.StatusOK, nonceW.Code)

	var nonceResp map[string]interface{}
	ts.Require().NoError(json.NewDecoder(nonceW.Body).Decode(&nonceResp))
	nonce, ok := nonceResp["nonce"].(string)
	ts.Require().True(ok)
	ts.Require().NotEmpty(nonce)

	rawMessage, signatureBase64 := ts.generateSIWSMessageAndSignature(nonce)

	const numConcurrentRequests = 10

	type result struct {
		statusCode int
		response   string
	}
	results := make(chan result, numConcurrentRequests)

	var wg sync.WaitGroup
	wg.Add(numConcurrentRequests)

	for i := 0; i < numConcurrentRequests; i++ {
		go func() {
			defer wg.Done()

			req := newSIWSRequest(ts.T(), grantTypeWeb3, rawMessage, signatureBase64, ts.pubKeyBase58, chainSolanaMainnet)
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)

			results <- result{
				statusCode: w.Code,
				response:  w.Body.String(),
			}
		}()
	}

	wg.Wait()
	close(results)

	successCount := 0
	failureCount := 0

	for r := range results {
		if r.statusCode == http.StatusOK {
			successCount++
		} else {
			failureCount++
		}
	}

	ts.Require().Equal(1, successCount, "Expected exactly one successful nonce usage")
	ts.Require().Equal(numConcurrentRequests-1, failureCount, "Expected all other requests to fail")

	storedNonce, err := FindStoredNonceByAddressAndNonce(ts.API.db, ts.pubKeyBase58, nonce)
	ts.Require().NoError(err)
	ts.Require().NotNil(storedNonce)
	ts.Require().True(storedNonce.Used)
}