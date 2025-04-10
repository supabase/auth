package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
)

type Web3TestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestWeb3(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &Web3TestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *Web3TestSuite) TestNonSolana() {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain": "blockchain",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	var firstResult struct {
		ErrorCode string `json:"error_code"`
		Message   string `json:"msg"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))
	assert.Equal(ts.T(), apierrors.ErrorCodeWeb3UnsupportedChain, firstResult.ErrorCode)
	assert.Equal(ts.T(), "Unsupported chain", firstResult.Message)
}

func (ts *Web3TestSuite) TestDisabled() {
	defer func() {
		ts.Config.External.Web3Solana.Enabled = true
	}()

	ts.Config.External.Web3Solana.Enabled = false

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain": "solana",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	var firstResult struct {
		ErrorCode string `json:"error_code"`
		Message   string `json:"msg"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))
	assert.Equal(ts.T(), apierrors.ErrorCodeWeb3ProviderDisabled, firstResult.ErrorCode)
	assert.Equal(ts.T(), "Web3 provider is disabled", firstResult.Message)
}

func (ts *Web3TestSuite) TestHappyPath_FullMessage() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:09:59Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z\nExpiration Time: 2025-03-29T00:10:00Z\nNot Before: 2025-03-29T00:00:00Z",
		"signature": "aiKn+PAoB1OoXxS8H34HrB456YD4sKAVjeTjsxgkaQy3bkdV51WBTmUUE9lBU9kuXr0hTLI+1aTn5TFRbIF8CA==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusOK, w.Code)

	var firstResult struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.NotEmpty(ts.T(), firstResult.AccessToken)
	assert.NotEmpty(ts.T(), firstResult.RefreshToken)
}

func (ts *Web3TestSuite) TestHappyPath_MinimalMessage() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:09:59Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z",
		"signature": "BQxBJ+g2xbMh0LqwYR4ULJ4l7jXFmz33urmp534MS0x7nrGRe2xYdFq41FiGrySX6RipzGqX4kS2vkQmi/+JCg==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusOK, w.Code)

	var firstResult struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.NotEmpty(ts.T(), firstResult.AccessToken)
	assert.NotEmpty(ts.T(), firstResult.RefreshToken)
}

func (ts *Web3TestSuite) TestValidationRules_URINotHTTPSButIsHTTP() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:00:00Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: http://supaabse.com\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z",
		"signature": "zkCDPRAgy3N6KaYJrFgoTGuR+DDn1T6WiC70/m4GSIKMN3rIIDRUHjX/+bDCRyPTq/nC8N9HkMUvoD86gpVKCw==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), firstResult.Error, "invalid_grant")
	assert.Equal(ts.T(), firstResult.ErrorDescription, "Signed Solana message is using URI which uses HTTP and hostname is not localhost, only HTTPS is allowed")
}

func (ts *Web3TestSuite) TestValidationRules_URINotAllowed() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:00:00Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.green wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.green/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z\nExpiration Time: 2025-03-29T00:10:00Z",
		"signature": "HlwIlZNfJO2yVqnJfeTz1sEHEbU0pag5yyfWVjmoL6wAXNshOlmQCgbzM8AvdF3/JpeWru2FUsC9cKHchHStDw==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), "invalid_grant", firstResult.Error)
	assert.Equal(ts.T(), "Signed Solana message is using URI which is not allowed on this server, message was signed for another app", firstResult.ErrorDescription)
}

func (ts *Web3TestSuite) TestValidationRules_URINotHTTPS() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:00:00Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: ftp://supaabse.com\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z",
		"signature": "jalHCMtaGNUy5q7BIZRXjdtMJDVDk+ABj/bsIISdbzxc4bjt643llZfjQ3qJJmV1CsnNRgoIyVt8HmGHkIu9CA==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), "invalid_grant", firstResult.Error)
	assert.Equal(ts.T(), "Signed Solana message is using URI which does not use HTTPS", firstResult.ErrorDescription)
}

func (ts *Web3TestSuite) TestValidationRules_InvalidDomain() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:00:00Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.green wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z",
		"signature": "gB9SNz/fxpWir6ZV/oI3pJIYEce5FjSMkbHzDxMH7k6as2jYBVutMU50/UTH59jx3ULZeW3Xt7pDH+9qJCDjAQ==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), "invalid_grant", firstResult.Error)
	assert.Equal(ts.T(), "Signed Solana message is using a Domain that does not match the one in URI which is not allowed on this server", firstResult.ErrorDescription)
}

func (ts *Web3TestSuite) TestValidationRules_MismatchedDomainAndURIHostname() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:00:00Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.green wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z\nExpiration Time: 2025-03-29T00:10:00Z",
		"signature": "KmRa5LqZnwLE5c+PX45QBhuIY2AXWtD8zi3O5lROKJYho8iIt8vZaVo/2utQ5C77LWNL3nI42q/cC8N80hYKAw==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), "invalid_grant", firstResult.Error)
	assert.Equal(ts.T(), "Signed Solana message is using a Domain that does not match the one in URI which is not allowed on this server", firstResult.ErrorDescription)
}

func (ts *Web3TestSuite) TestValidationRules_ValidatedBeforeNotBefore() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:00:59Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z\nNot Before: 2025-03-29T00:01:00Z",
		"signature": "Pe2PpPEK+SIsO3i26SsWNHeFyLKNdcms4Gf7jy8GGR6EvPlWfKNwAtRGMnQa9MvQHgY7QmVOUDSKmYQlvU2sAA==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), "invalid_grant", firstResult.Error)
	assert.Equal(ts.T(), "Signed Solana message becomes valid in the future", firstResult.ErrorDescription)
}

func (ts *Web3TestSuite) TestValidationRules_Expired() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:10:01Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z\nExpiration Time: 2025-03-29T00:10:00Z\nNot Before: 2025-03-29T00:00:00Z",
		"signature": "aiKn+PAoB1OoXxS8H34HrB456YD4sKAVjeTjsxgkaQy3bkdV51WBTmUUE9lBU9kuXr0hTLI+1aTn5TFRbIF8CA==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), "invalid_grant", firstResult.Error)
	assert.Equal(ts.T(), "Signed Solana message is expired", firstResult.ErrorDescription)
}

func (ts *Web3TestSuite) TestValidationRules_Future() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-28T23:49:59Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z",
		"signature": "BQxBJ+g2xbMh0LqwYR4ULJ4l7jXFmz33urmp534MS0x7nrGRe2xYdFq41FiGrySX6RipzGqX4kS2vkQmi/+JCg==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), "invalid_grant", firstResult.Error)
	assert.Equal(ts.T(), "Solana message was issued too far in the future", firstResult.ErrorDescription)
}

func (ts *Web3TestSuite) TestValidationRules_IssedTooLongAgo() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:00:00Z")
		d, _ := time.ParseDuration("10m1s")

		return t.Add(d)
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z\nNot Before: 2025-03-29T00:00:00Z",
		"signature": "ds3yyRoevZ0CuyUFOfuAJV/QAA+m302JJjnkOQO3ou5AHPQBNdbwYDj2JzF/5Ox6qyAqN/phU8NnmK8eUtzMDw==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), firstResult.Error, "invalid_grant")
	assert.Equal(ts.T(), firstResult.ErrorDescription, "Solana message was issued too long ago")
}

func (ts *Web3TestSuite) TestValidationRules_InvalidSignature() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		t, _ := time.Parse(time.RFC3339, "2025-03-29T00:00:00Z")
		return t
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   "supabase.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nStatement\n\nURI: https://supabase.com/\nVersion: 1\nIssued At: 2025-03-29T00:00:00Z\nExpiration Time: 2025-03-29T00:10:00Z\nNot Before: 2025-03-29T00:00:00Z",
		"signature": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	var firstResult struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	assert.NoError(ts.T(), json.NewDecoder(w.Result().Body).Decode(&firstResult))

	assert.Equal(ts.T(), firstResult.Error, "invalid_grant")
	assert.Equal(ts.T(), firstResult.ErrorDescription, "Signature does not match address in message")
}

func (ts *Web3TestSuite) TestValidationRules_BasicValidation() {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   strings.Repeat(" ", 63),
		"signature": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   strings.Repeat(" ", 64),
		"signature": strings.Repeat("x", 85),
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   strings.Repeat(" ", 64),
		"signature": strings.Repeat("x", 89),
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   strings.Repeat(" ", 20*1024+1),
		"signature": strings.Repeat("x", 86),
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   strings.Repeat(" ", 64),
		"signature": strings.Repeat("\x00", 86),
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)

	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"message":   strings.Repeat(" ", 64),
		"signature": strings.Repeat("x", 86),
	}))

	req = httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=web3", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}
