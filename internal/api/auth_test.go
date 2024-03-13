package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type AuthTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestAuth(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &AuthTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()
	suite.Run(t, ts)
}

func (ts *AuthTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	// Create user
	u, err := models.NewUser("", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating test user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new test user")
}

func (ts *AuthTestSuite) TestExtractBearerToken() {
	userClaims := &AccessTokenClaims{
		Role: "authenticated",
	}
	userJwt, err := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err)
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Authorization", "Bearer "+userJwt)

	token, err := ts.API.extractBearerToken(req)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), userJwt, token)
}

func (ts *AuthTestSuite) TestParseJWTClaims() {
	userClaims := &AccessTokenClaims{
		Role: "authenticated",
	}
	userJwt, err := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err)

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Authorization", "Bearer "+userJwt)
	ctx, err := ts.API.parseJWTClaims(userJwt, req)
	require.NoError(ts.T(), err)

	// check if token is stored in context
	token := getToken(ctx)
	require.Equal(ts.T(), userJwt, token.Raw)
}

func (ts *AuthTestSuite) TestMaybeLoadUserOrSession() {
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	s, err := models.NewSession(u.ID, nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(s))

	require.NoError(ts.T(), ts.API.db.Load(s))

	cases := []struct {
		Desc            string
		UserJwtClaims   *AccessTokenClaims
		ExpectedError   error
		ExpectedUser    *models.User
		ExpectedSession *models.Session
	}{
		{
			Desc: "Missing Subject Claim",
			UserJwtClaims: &AccessTokenClaims{
				StandardClaims: jwt.StandardClaims{
					Subject: "",
				},
				Role: "authenticated",
			},
			ExpectedError: forbiddenError(ErrorCodeBadJWT, "invalid claim: missing sub claim"),
			ExpectedUser:  nil,
		},
		{
			Desc: "Valid Subject Claim",
			UserJwtClaims: &AccessTokenClaims{
				StandardClaims: jwt.StandardClaims{
					Subject: u.ID.String(),
				},
				Role: "authenticated",
			},
			ExpectedError: nil,
			ExpectedUser:  u,
		},
		{
			Desc: "Invalid Subject Claim",
			UserJwtClaims: &AccessTokenClaims{
				StandardClaims: jwt.StandardClaims{
					Subject: "invalid-subject-claim",
				},
				Role: "authenticated",
			},
			ExpectedError: badRequestError(ErrorCodeBadJWT, "invalid claim: sub claim must be a UUID"),
			ExpectedUser:  nil,
		},
		{
			Desc: "Empty Session ID Claim",
			UserJwtClaims: &AccessTokenClaims{
				StandardClaims: jwt.StandardClaims{
					Subject: u.ID.String(),
				},
				Role:      "authenticated",
				SessionId: "",
			},
			ExpectedError: nil,
			ExpectedUser:  u,
		},
		{
			Desc: "Invalid Session ID Claim",
			UserJwtClaims: &AccessTokenClaims{
				StandardClaims: jwt.StandardClaims{
					Subject: u.ID.String(),
				},
				Role:      "authenticated",
				SessionId: uuid.Nil.String(),
			},
			ExpectedError: nil,
			ExpectedUser:  u,
		},
		{
			Desc: "Valid Session ID Claim",
			UserJwtClaims: &AccessTokenClaims{
				StandardClaims: jwt.StandardClaims{
					Subject: u.ID.String(),
				},
				Role:      "authenticated",
				SessionId: s.ID.String(),
			},
			ExpectedError:   nil,
			ExpectedUser:    u,
			ExpectedSession: s,
		},
	}

	for _, c := range cases {
		ts.Run(c.Desc, func() {
			userJwt, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c.UserJwtClaims).SignedString([]byte(ts.Config.JWT.Secret))
			require.NoError(ts.T(), err)

			req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			req.Header.Set("Authorization", "Bearer "+userJwt)

			ctx, err := ts.API.parseJWTClaims(userJwt, req)
			require.NoError(ts.T(), err)
			ctx, err = ts.API.maybeLoadUserOrSession(ctx)
			if c.ExpectedError != nil {
				require.Equal(ts.T(), c.ExpectedError.Error(), err.Error())
			} else {
				require.Equal(ts.T(), c.ExpectedError, err)
			}
			require.Equal(ts.T(), c.ExpectedUser, getUser(ctx))
			require.Equal(ts.T(), c.ExpectedSession, getSession(ctx))
		})
	}
}
