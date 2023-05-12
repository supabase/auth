package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"github.com/supabase/gotrue/internal/models"
)

type MailTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestMail(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &MailTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *MailTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)

	ts.Config.Mailer.SecureEmailChangeEnabled = true

	// Create User
	u, err := models.NewUser("12345678", "test@example.com", "password", ts.Config.JWT.Aud, nil)
	require.NoError(ts.T(), err, "Error creating new user model")
	require.NoError(ts.T(), ts.API.db.Create(u), "Error saving new user")
}

func (ts *MailTestSuite) TestGenerateLink() {
	// create admin jwt
	claims := &GoTrueClaims{
		Role: "supabase_admin",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ts.Config.JWT.Secret))
	require.NoError(ts.T(), err, "Error generating admin jwt")

	// create test cases
	cases := []struct {
		Desc         string
		Body         GenerateLinkParams
		ExpectedCode int
	}{
		{
			Desc: "Generate signup link",
			Body: GenerateLinkParams{
				Email:    "test@example.com",
				Password: "secret123",
				Type:     "signup",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			Desc: "Generate magic link",
			Body: GenerateLinkParams{
				Email: "test@example.com",
				Type:  "magiclink",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			Desc: "Generate invite link",
			Body: GenerateLinkParams{
				Email: "test@example.com",
				Type:  "invite",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			Desc: "Generate recovery link",
			Body: GenerateLinkParams{
				Email: "test@example.com",
				Type:  "recovery",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			Desc: "Generate email change link",
			Body: GenerateLinkParams{
				Email:    "test@example.com",
				NewEmail: "new@example.com",
				Type:     "email_change_current",
			},
			ExpectedCode: http.StatusOK,
		},
		{
			Desc: "Generate email change link",
			Body: GenerateLinkParams{
				Email:    "test@example.com",
				NewEmail: "new@example.com",
				Type:     "email_change_new",
			},
			ExpectedCode: http.StatusOK,
		},
	}

	customDomainUrl, err := url.ParseRequestURI("https://example.gotrue.com")
	require.NoError(ts.T(), err)

	for _, c := range cases {
		ts.Run(c.Desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.Body))
			req := httptest.NewRequest(http.MethodPost, customDomainUrl.String()+"/admin/generate_link", &buffer)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
			w := httptest.NewRecorder()

			ts.API.handler.ServeHTTP(w, req)

			require.Equal(ts.T(), c.ExpectedCode, w.Code)

			data := make(map[string]interface{})
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

			require.Contains(ts.T(), data, "action_link")
			require.Contains(ts.T(), data, "email_otp")
			require.Contains(ts.T(), data, "hashed_token")
			require.Contains(ts.T(), data, "redirect_to")
			require.Equal(ts.T(), c.Body.Type, data["verification_type"])

			// check if hashed_token matches hash function of email and the raw otp
			require.Equal(ts.T(), data["hashed_token"], fmt.Sprintf("%x", sha256.Sum224([]byte(c.Body.Email+data["email_otp"].(string)))))

			// check if the host used in the email link matches the initial request host
			u, err := url.ParseRequestURI(data["action_link"].(string))
			require.NoError(ts.T(), err)
			require.Equal(ts.T(), req.Host, u.Host)
		})
	}
}
