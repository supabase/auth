package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
)

func (ts *ExternalTestSuite) TestLinkIdentityWithIDToken_Apple() {
	// Setup user to link with
	existingUser, err := ts.createUser("existing123", "existing@example.com", "Existing User", "", "")
	ts.Require().NoError(err)

	// Create a session for the user
	session, err := models.NewSession(existingUser.ID, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(session))

	// Generate access token for authentication
	token, _, err := ts.API.generateAccessToken(httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil), ts.API.db, existingUser, &session.ID, models.PasswordGrant)
	ts.Require().NoError(err)

	// Simulated Apple ID token data
	appleUserData := &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    "apple@example.com",
				Verified: true,
				Primary:  true,
			},
		},
		Metadata: &provider.Claims{
			Subject: "apple123",
			Name:    "Apple Test User",
		},
	}

	// Simulate an Apple ID token by encoding user data
	idToken := ts.mockAppleIDToken(appleUserData)

	// Create the request
	reqData := map[string]interface{}{
		"id_token": idToken,
		"provider": "apple",
	}
	reqBody, err := json.Marshal(reqData)
	ts.Require().NoError(err)

	req := httptest.NewRequest(http.MethodPost, "/user/identities/link_token", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	ts.Require().Equal(http.StatusOK, w.Code)

	// Verify the user now has the linked identity
	updatedUser, err := models.FindUserByID(ts.API.db, existingUser.ID)
	ts.Require().NoError(err)

	// Load identities
	ts.API.db.Load(updatedUser, "Identities")

	// Verify that the new Apple identity was added
	var found bool
	for _, identity := range updatedUser.Identities {
		if identity.Provider == "apple" && identity.ProviderID == "apple123" {
			found = true
			// Verify identity data
			ts.Equal("Apple Test User", identity.IdentityData["name"])
			break
		}
	}
	ts.True(found, "Apple identity should be linked to user")

	// Verify providers in app metadata
	providers, ok := updatedUser.AppMetaData["providers"].([]interface{})
	ts.True(ok, "providers should exist in app_metadata")
	ts.Contains(providers, "apple", "providers should include apple")
	ts.Contains(providers, "email", "providers should maintain existing email provider")
}

func (ts *ExternalTestSuite) TestLinkIdentityWithIDToken_AppleAlreadyLinked() {
	// Setup first user with Apple identity
	firstUser, err := ts.createUser("user1", "user1@example.com", "First User", "", "")
	ts.Require().NoError(err)

	// Create Apple identity for first user
	appleIdentity, err := models.NewIdentity(firstUser, "apple", map[string]interface{}{
		"sub":  "apple123",
		"name": "Apple User",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(appleIdentity))

	// Setup second user who will attempt to link
	secondUser, err := ts.createUser("user2", "user2@example.com", "Second User", "", "")
	ts.Require().NoError(err)

	// Create session for second user
	session, err := models.NewSession(secondUser.ID, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(session))

	// Generate access token for second user
	token, _, err := ts.API.generateAccessToken(httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil), ts.API.db, secondUser, &session.ID, models.PasswordGrant)
	ts.Require().NoError(err)

	// Create the link request with same Apple identity
	reqData := map[string]interface{}{
		"id_token": ts.mockAppleIDToken(&provider.UserProvidedData{
			Emails: []provider.Email{{Email: "apple@example.com", Verified: true, Primary: true}},
			Metadata: &provider.Claims{
				Subject: "apple123",
				Name:    "Apple Test User",
			},
		}),
		"provider": "apple",
	}
	reqBody, err := json.Marshal(reqData)
	ts.Require().NoError(err)

	req := httptest.NewRequest(http.MethodPost, "/user/identities/link_token", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	ts.Require().Equal(http.StatusUnprocessableEntity, w.Code)
	
	var response map[string]interface{}
	err = json.NewDecoder(w.Body).Decode(&response)
	ts.Require().NoError(err)
	ts.Equal("identity_already_exists", response["code"])
	ts.Equal("Identity is already linked to another user", response["msg"])
}

func (ts *ExternalTestSuite) TestLinkIdentityWithIDToken_NoAuth() {
	reqData := map[string]interface{}{
		"id_token": "test_token",
		"provider": "apple",
	}
	reqBody, err := json.Marshal(reqData)
	ts.Require().NoError(err)

	req := httptest.NewRequest(http.MethodPost, "/user/identities/link_token", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	ts.Require().Equal(http.StatusUnauthorized, w.Code)
}

// Helper function to mock Apple ID token
func (ts *ExternalTestSuite) mockAppleIDToken(userData *provider.UserProvidedData) string {
	// In a real implementation, you would create a proper JWT
	// For testing purposes, we'll create a simple token that the mocked provider can understand
	claims := map[string]interface{}{
		"sub":   userData.Metadata.Subject,
		"name":  userData.Metadata.Name,
		"email": userData.Emails[0].Email,
		"iss":   "https://appleid.apple.com",
		"aud":   ts.Config.External.Apple.ClientID[0],
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	tokenString, err := token.SignedString([]byte(ts.Config.JWT.Secret))
	ts.Require().NoError(err)
	
	return tokenString
}