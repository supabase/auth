package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
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
	assert.Equal(ts.T(), ErrorCodeWeb3UnsupportedChain, firstResult.ErrorCode)
	assert.Equal(ts.T(), "Unsupported chain", firstResult.Message)
}

func (ts *Web3TestSuite) TestDisabled() {
	defer func() {
		ts.Config.External.Web3.Enabled = true
	}()

	ts.Config.External.Web3.Enabled = false

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
	assert.Equal(ts.T(), ErrorCodeWeb3ProviderDisabled, firstResult.ErrorCode)
	assert.Equal(ts.T(), "Web3 provider is disabled", firstResult.Message)
}

func (ts *Web3TestSuite) TestHappyPath() {
	defer func() {
		ts.API.overrideTime = nil
	}()

	ts.API.overrideTime = func() time.Time {
		return time.UnixMilli(1742840411629)
	}

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"chain":     "solana",
		"signature": "gRaUDNnz5nsTERT9udZgK5rqVt_P5sVEzgYFCLtEUo2DXfIQBTFJM2CghGWVKoCvPuz-DePAgOs2Fe_z-ZdgBQ",
		"message":   "phantom.com wants you to sign in with your Solana account:\n2EZEiBdw47VHT6SpZSW9VnuSvBe7DxuYHBTxj19gxvv8\n\nsupabase/auth tests\n\nURI: https://phantom.com/download\nVersion: 1\nIssued At: 2025-03-24T18:20:11.629Z",
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
