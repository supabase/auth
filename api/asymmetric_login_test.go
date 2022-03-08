package api

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

type ChallengeTokenTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.Configuration
}

func TestGetChallengeToken(t *testing.T) {
	api, config, _, err := setupAPIForTestForInstance()
	require.NoError(t, err)

	ts := &ChallengeTokenTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *ChallengeTokenTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
}

// TestSignup tests API /signup route
func (ts *SignupTestSuite) TestSuccessfulGetChallengeToken() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":       "0x6BE46d7D863666546b77951D5dfffcF075F36E68",
		"algorithm": "ETH",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/sign_challenge", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	jsonData := GetChallengeTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&jsonData))
	require.NotEmpty(ts.T(), jsonData)

	user, key, err := models.FindUserWithAsymmetrickey(ts.API.db, "0x6BE46d7D863666546b77951D5dfffcF075F36E68")
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), user)
	require.NotEmpty(ts.T(), key)
	assert.Equal(ts.T(), key.ChallengeToken.String(), jsonData.ChallengeToken)

}

func (ts *SignupTestSuite) TestWrongAlgorithmGetChallengeToken() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":       "0x6BE46d7D863666546b77951D5dfffcF075F36E68",
		"algorithm": "test",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/sign_challenge", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code)

	msg, err := ioutil.ReadAll(w.Body)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []byte(`{"code":422,"msg":"Key verification failed: Provided algorithm is not supported"}`), msg)
}

func (ts *SignupTestSuite) TestWrongKeyFormatGetChallengeToken() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":       "testtest",
		"algorithm": "ETH",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/sign_challenge", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code)

	msg, err := ioutil.ReadAll(w.Body)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []byte(`{"code":422,"msg":"Key verification failed: Provided key cannot be ETH address"}`), msg)
}

func (ts *SignupTestSuite) TestFirstSignInSuperAdmin() {
	//FirstUser is SuperAdmin config on true
	ts.Config.FirstUserSuperAdmin = true

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":       "0x6BE46d7D863666546b77951D5dfffcF075F36E68",
		"algorithm": "ETH",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/sign_challenge", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	jsonData := GetChallengeTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&jsonData))
	require.NotEmpty(ts.T(), jsonData)

	user, key, err := models.FindUserWithAsymmetrickey(ts.API.db, "0x6BE46d7D863666546b77951D5dfffcF075F36E68")
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), user)
	require.NotEmpty(ts.T(), key)
	assert.Equal(ts.T(), key.ChallengeToken.String(), jsonData.ChallengeToken)
	assert.Equal(ts.T(), user.Role, "superadmin")
	assert.Equal(ts.T(), user.IsSuperAdmin, true)
}

func (ts *SignupTestSuite) TestFirstSignInConfigFalse() {
	//FirstUser is SuperAdmin config on false
	ts.Config.FirstUserSuperAdmin = false

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":       "0x6BE46d7D863666546b77951D5dfffcF075F36E68",
		"algorithm": "ETH",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/sign_challenge", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	jsonData := GetChallengeTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&jsonData))
	require.NotEmpty(ts.T(), jsonData)

	user, key, err := models.FindUserWithAsymmetrickey(ts.API.db, "0x6BE46d7D863666546b77951D5dfffcF075F36E68")
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), user)
	require.NotEmpty(ts.T(), key)
	assert.Equal(ts.T(), key.ChallengeToken.String(), jsonData.ChallengeToken)
	assert.Equal(ts.T(), user.Role, "authenticated")
	assert.Equal(ts.T(), user.IsSuperAdmin, false)
}

func (ts *SignupTestSuite) TestNotFirstSignIn() {
	//FirstUser is SuperAdmin config on true
	ts.Config.FirstUserSuperAdmin = true

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":       "0x6BE46d7D863666546b77951D5dfffcF075F36E68",
		"algorithm": "ETH",
	}))

	var buffer2 bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer2).Encode(map[string]interface{}{
		"key":       "0x6BE46d7D863666546677951D5dfffcF075F36E68",
		"algorithm": "ETH",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/sign_challenge", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	req = httptest.NewRequest(http.MethodPost, "/sign_challenge", &buffer2)
	req.Header.Set("Content-Type", "application/json")

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	jsonData := GetChallengeTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&jsonData))
	require.NotEmpty(ts.T(), jsonData)

	user, key, err := models.FindUserWithAsymmetrickey(ts.API.db, "0x6BE46d7D863666546677951D5dfffcF075F36E68")
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), user)
	require.NotEmpty(ts.T(), key)
	assert.Equal(ts.T(), user.Role, "authenticated")
	assert.Equal(ts.T(), user.IsSuperAdmin, false)
}

type AsymmetricSignInTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.Configuration

	privateKey     *ecdsa.PrivateKey
	address        string
	challengeToken string
}

func TestSignInWithAsymmetricKey(t *testing.T) {
	api, config, _, err := setupAPIForTestForInstance()
	require.NoError(t, err)

	ts := &AsymmetricSignInTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *AsymmetricSignInTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	privateKey, err := crypto.GenerateKey()
	require.NoError(ts.T(), err)
	ts.privateKey = privateKey
	ts.address = crypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":       ts.address,
		"algorithm": "ETH",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/sign_challenge", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusOK, w.Code)
	jsonData := GetChallengeTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&jsonData))
	require.NotEmpty(ts.T(), jsonData)
	ts.challengeToken = jsonData.ChallengeToken
}

func (ts *AsymmetricSignInTestSuite) TestSuccessfulSignIn() {
	hash := models.SignEthMessageHash([]byte(ts.challengeToken))
	signature, err := crypto.Sign(hash, ts.privateKey)
	require.NoError(ts.T(), err)
	fmt.Println("Signature1:", hexutil.Encode(signature))
	signature[64] += 27

	fmt.Println("Signature2:", hexutil.Encode(signature))

	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":                       ts.address,
		"challenge_token_signature": hexutil.Encode(signature),
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/asymmetric_login", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	jsonData := AccessTokenResponse{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&jsonData))
	require.NotEmpty(ts.T(), jsonData)

	jwtToken, err := jwt.ParseWithClaims(jsonData.Token, &GoTrueClaims{}, func(token *jwt.Token) (interface{}, error) {
		return ts.Config.JWT.GetVerificationKey(), nil
	})
	require.NoError(ts.T(), err)
	require.True(ts.T(), jwtToken.Valid)

	claims, ok := jwtToken.Claims.(*GoTrueClaims)
	require.True(ts.T(), ok)

	require.Equal(ts.T(), ts.address, claims.MainAsymmetricKey)
	require.Equal(ts.T(), "ETH", claims.MainAsymmetricKeyAlgorithm)
}

func (ts *AsymmetricSignInTestSuite) TestSignatureWithout0xPrefixSignIn() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":                       ts.address,
		"challenge_token_signature": "testest",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/asymmetric_login", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code)

	msg, err := ioutil.ReadAll(w.Body)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []byte(`{"code":422,"msg":"Signature verification failed:hex string without 0x prefix"}`), msg)
}

func (ts *AsymmetricSignInTestSuite) TestWrongSignatureFormatSignIn() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":                       ts.address,
		"challenge_token_signature": "0x39c95778651840beee168d95577abe5e42d83bf88ba6e39569de2d2bd674da6f2844a42d45206f09f945fb1768e9c7045e818ea5bee0dce1258005e43855b50601",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/asymmetric_login", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code)

	msg, err := ioutil.ReadAll(w.Body)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []byte(`{"code":422,"msg":"Signature verification failed:Provided signature has wrong format"}`), msg)
}

func (ts *AsymmetricSignInTestSuite) TestAnotherKeySignatureSignIn() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":                       ts.address,
		"challenge_token_signature": "0x89568ade6b6f87652de7832b83652176788862bf6b2EB4260ef8d7f98dc067475e2d0fdb2aee6c5630d94e3c4a596acd8c62ce97bce2946f2003908c375116da1c",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/asymmetric_login", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusUnprocessableEntity, w.Code)

	msg, err := ioutil.ReadAll(w.Body)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []byte(`{"code":422,"msg":"Signature verification failed:Provided signature does not match with Key"}`), msg)
}

func (ts *AsymmetricSignInTestSuite) TestMissingKeySignIn() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"key":                       "0x6BE46d7D863666546b77951D5dfffcF075F36E68",
		"challenge_token_signature": "0x89568ade6b6f87652de7832b83652176788862bf6b2EB4260ef8d7f98dc067475e2d0fdb2aee6c5630d94e3c4a596acd8c62ce97bce2946f2003908c375116da1c",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/asymmetric_login", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), http.StatusUnauthorized, w.Code)

	msg, err := ioutil.ReadAll(w.Body)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), []byte(`{"code":401,"msg":"Unauthorized"}`), msg)
}
