package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/netlify/gotrue/storage"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type TokenTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.Configuration

	RefreshToken *models.RefreshToken
	instanceID   uuid.UUID
}

func TestToken(t *testing.T) {
	os.Setenv("GOTRUE_RATE_LIMIT_HEADER", "My-Custom-Header")
	api, config, instanceID, err := setupAPIForTestForInstance()
	require.NoError(t, err)

	ts := &TokenTestSuite{
		API:        api,
		Config:     config,
		instanceID: instanceID,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *TokenTestSuite) SetupTest() {
	ts.RefreshToken = nil
	models.TruncateAll(ts.API.db)

	// Create user & refresh token
	u, err := models.NewUser(ts.instanceID, "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	t := time.Now()
	u.EmailConfirmedAt = &t
	u.BannedUntil = nil
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")

	ts.RefreshToken, err = models.GrantAuthenticatedUser(ts.API.db, u)
	require.NoError(ts.T(), err, "Error creating refresh token")
}

func (ts *TokenTestSuite) TestRateLimitToken() {
	var buffer bytes.Buffer
	req := httptest.NewRequest(http.MethodPost, "http://localhost/token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("My-Custom-Header", "1.2.3.4")

	// It rate limits after 30 requests
	for i := 0; i < 30; i++ {
		w := httptest.NewRecorder()
		ts.API.handler.ServeHTTP(w, req)
		assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
	}
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

	// It ignores X-Forwarded-For by default
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusTooManyRequests, w.Code)

	// It doesn't rate limit a new value for the limited header
	req = httptest.NewRequest(http.MethodPost, "http://localhost/token", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("My-Custom-Header", "5.6.7.8")
	w = httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}

func (ts *TokenTestSuite) TestTokenPasswordGrantSuccess() {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    "test@example.com",
		"password": "password",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *TokenTestSuite) TestTokenRefreshTokenGrantSuccess() {
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": ts.RefreshToken.Token,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusOK, w.Code)
}

func (ts *TokenTestSuite) TestTokenPasswordGrantFailure() {
	u := ts.createBannedUser()

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    u.GetEmail(),
		"password": "password",
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=password", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}

func (ts *TokenTestSuite) TestTokenRefreshTokenGrantFailure() {
	_ = ts.createBannedUser()

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"refresh_token": ts.RefreshToken.Token,
	}))

	req := httptest.NewRequest(http.MethodPost, "http://localhost/token?grant_type=refresh_token", &buffer)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusBadRequest, w.Code)
}

func (ts *TokenTestSuite) createBannedUser() *models.User {
	u, err := models.NewUser(ts.instanceID, "banned@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	t := time.Now()
	u.EmailConfirmedAt = &t
	t = t.Add(24 * time.Hour)
	u.BannedUntil = &t
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test banned user")

	ts.RefreshToken, err = models.GrantAuthenticatedUser(ts.API.db, u)
	require.NoError(ts.T(), err, "Error creating refresh token")

	return u
}

func (ts *TokenTestSuite) TestRSAToken() {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(ts.T(), err)

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privatekey)
	require.NoError(ts.T(), err)

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)

	ts.Config.JWT.Secret = base64.URLEncoding.EncodeToString(keyPEM)
	ts.Config.JWT.Algorithm = "RS256"
	ts.Config.JWT.InitializeSigningSecret()

	ctx, err := WithInstanceConfig(context.Background(), ts.Config, uuid.Nil)

	var token *AccessTokenResponse
	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		user, terr := ts.API.signupNewUser(ctx, ts.API.db, &SignupParams{
			Aud: "authenticated",
		})
		if terr != nil {
			return terr
		}

		token, err = ts.API.issueRefreshToken(ctx, tx, user)
		return err
	})
	require.NoError(ts.T(), err)

	jwtToken, err := jwt.ParseWithClaims(token.Token, &GoTrueClaims{}, func(token *jwt.Token) (interface{}, error) {
		return ts.Config.JWT.GetVerificationKey(), nil
	})

	require.NoError(ts.T(), err)
	require.True(ts.T(), jwtToken.Valid)
	require.Equal(ts.T(), jwt.SigningMethodRS256, jwtToken.Method)

	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"password": "newpass",
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodGet, "http://localhost/user", &buffer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Token))

	// Setup response recorder
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	require.Equal(ts.T(), w.Code, http.StatusOK)
}
