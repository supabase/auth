package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
)

func (ts *ExternalTestSuite) TestSignupExternalApple() {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/authorize?provider=apple", nil)
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	ts.Require().Equal(http.StatusFound, w.Code)
	u, err := url.Parse(w.Header().Get("Location"))
	ts.Require().NoError(err, "redirect url parse failed")
	q := u.Query()
	ts.Equal(ts.Config.External.Apple.RedirectURI, q.Get("redirect_uri"))
	ts.Equal(ts.Config.External.Apple.ClientID, []string{q.Get("client_id")})
	ts.Equal("code", q.Get("response_type"))
	ts.Equal("email name", q.Get("scope"))

	assertValidOAuthState(ts, q.Get("state"), "apple")
}

func (ts *ExternalTestSuite) TestAppleRelayEmailConflict() {
	// 1. Create Apple relay user (User A)
	userA, err := models.NewUser("", "anon@privaterelay.appleid.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userA))

	identityA, err := models.NewIdentity(userA, "apple", map[string]interface{}{
		"sub":   "apple-sub-123",
		"email": "anon@privaterelay.appleid.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityA))

	// 2. Create standard Google user (User B)
	userB, err := models.NewUser("", "user@gmail.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userB))

	identityB, err := models.NewIdentity(userB, "google", map[string]interface{}{
		"sub":   "google-sub-456",
		"email": "user@gmail.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityB))

	// 3. Perform Apple login returning the primary email (user@gmail.com)
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	userData := &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    "user@gmail.com",
				Verified: true,
				Primary:  true,
			},
		},
		Metadata: &provider.Claims{
			Subject: "apple-sub-123",
		},
	}

	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		decision, resolvedUser, terr := ts.API.createAccountFromExternalIdentity(tx, req, userData, "apple", false)
		ts.Require().NoError(terr)
		ts.Equal(models.AccountExists, decision)
		ts.Equal(userA.ID, resolvedUser.ID)
		return nil
	})
	ts.Require().NoError(err)

	// 4. Verification Pass:
	// - auth.users.email remains unchanged
	dbUserA, terr := models.FindUserByID(ts.API.db, userA.ID)
	ts.Require().NoError(terr)
	ts.Equal("anon@privaterelay.appleid.com", dbUserA.GetEmail())

	// - auth.identities.email remains unchanged
	persistedIdentity, terr := models.FindIdentityByIdAndProvider(ts.API.db, "apple-sub-123", "apple")
	ts.Require().NoError(terr)
	ts.Equal("anon@privaterelay.appleid.com", persistedIdentity.IdentityData["email"].(string))

	// - No duplicate identity rows are created
	var count int
	err = ts.API.db.Q().RawQuery("select count(*) from identities where provider = 'apple' and provider_id = 'apple-sub-123'").First(&count)
	ts.Require().NoError(err)
	ts.Equal(1, count)
}

func (ts *ExternalTestSuite) TestAppleRelayNoConflict() {
	// Scenario: Apple relay -> primary email (no duplicate user exists)
	userA, err := models.NewUser("", "anon@privaterelay.appleid.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userA))

	identityA, err := models.NewIdentity(userA, "apple", map[string]interface{}{
		"sub":   "apple-sub-123",
		"email": "anon@privaterelay.appleid.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityA))

	// User logs in with Apple again, Apple returns primary email user@gmail.com
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	userData := &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    "user@gmail.com",
				Verified: true,
				Primary:  true,
			},
		},
		Metadata: &provider.Claims{
			Subject: "apple-sub-123",
		},
	}

	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		decision, resolvedUser, terr := ts.API.createAccountFromExternalIdentity(tx, req, userData, "apple", false)
		ts.Require().NoError(terr)
		ts.Equal(models.AccountExists, decision)
		ts.Equal(userA.ID, resolvedUser.ID)
		return nil
	})
	ts.Require().NoError(err)

	// Since no duplicate user exists, identity email should update to primary email
	persistedIdentity, terr := models.FindIdentityByIdAndProvider(ts.API.db, "apple-sub-123", "apple")
	ts.Require().NoError(terr)
	ts.Equal("user@gmail.com", persistedIdentity.IdentityData["email"].(string))

	// Only one identity exists
	var count int
	err = ts.API.db.Q().RawQuery("select count(*) from identities where provider = 'apple' and provider_id = 'apple-sub-123'").First(&count)
	ts.Require().NoError(err)
	ts.Equal(1, count)
}

func (ts *ExternalTestSuite) TestIdentityLinkingAfterFix() {
	// Scenario: Attempt to manually link the Apple identity to another existing user (User B)
	// and verify it returns expected "already linked" error instead of silently merging or throwing 500.
	userA, err := models.NewUser("", "anon@privaterelay.appleid.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userA))

	identityA, err := models.NewIdentity(userA, "apple", map[string]interface{}{
		"sub":   "apple-sub-123",
		"email": "anon@privaterelay.appleid.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityA))

	userB, err := models.NewUser("", "user@gmail.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userB))

	// Attempt manual link of Apple identity to User B
	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	userData := &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    "anon@privaterelay.appleid.com",
				Verified: true,
				Primary:  true,
			},
		},
		Metadata: &provider.Claims{
			Subject: "apple-sub-123",
		},
	}

	ctx := withTargetUser(req.Context(), userB)
	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		_, terr := ts.API.linkIdentityToUser(req, ctx, tx, userData, "apple")
		ts.Require().Error(terr)
		ts.Contains(terr.Error(), "Identity is already linked to another user")
		return nil
	})
	ts.Require().NoError(err)
}

func (ts *ExternalTestSuite) TestAppleRepeatedLogins() {
	userA, err := models.NewUser("", "anon@privaterelay.appleid.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userA))

	identityA, err := models.NewIdentity(userA, "apple", map[string]interface{}{
		"sub":   "apple-sub-123",
		"email": "anon@privaterelay.appleid.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityA))

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	userData := &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    "anon@privaterelay.appleid.com",
				Verified: true,
				Primary:  true,
			},
		},
		Metadata: &provider.Claims{
			Subject: "apple-sub-123",
		},
	}

	// Repeated logins
	for i := 0; i < 3; i++ {
		err = ts.API.db.Transaction(func(tx *storage.Connection) error {
			decision, _, terr := ts.API.createAccountFromExternalIdentity(tx, req, userData, "apple", false)
			ts.Require().NoError(terr)
			ts.Equal(models.AccountExists, decision)
			return nil
		})
		ts.Require().NoError(err)
	}
}

func (ts *ExternalTestSuite) TestGoogleAndAppleCoexistence() {
	userA, err := models.NewUser("", "anon@privaterelay.appleid.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userA))

	identityA, err := models.NewIdentity(userA, "apple", map[string]interface{}{
		"sub":   "apple-sub-123",
		"email": "anon@privaterelay.appleid.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityA))

	userB, err := models.NewUser("", "user@gmail.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userB))

	identityB, err := models.NewIdentity(userB, "google", map[string]interface{}{
		"sub":   "google-sub-456",
		"email": "user@gmail.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityB))

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	userData := &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    "user@gmail.com",
				Verified: true,
				Primary:  true,
			},
		},
		Metadata: &provider.Claims{
			Subject: "google-sub-456",
		},
	}

	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		decision, resolvedUser, terr := ts.API.createAccountFromExternalIdentity(tx, req, userData, "google", false)
		ts.Require().NoError(terr)
		ts.Equal(models.AccountExists, decision)
		ts.Equal(userB.ID, resolvedUser.ID)
		return nil
	})
	ts.Require().NoError(err)
}

func (ts *ExternalTestSuite) TestEmailAndPasswordAndAppleCoexistence() {
	userA, err := models.NewUser("", "anon@privaterelay.appleid.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userA))

	identityA, err := models.NewIdentity(userA, "apple", map[string]interface{}{
		"sub":   "apple-sub-123",
		"email": "anon@privaterelay.appleid.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityA))

	userB, err := models.NewUser("", "user@gmail.com", "test", ts.Config.JWT.Aud, nil)
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(userB))

	identityB, err := models.NewIdentity(userB, "email", map[string]interface{}{
		"sub":   userB.ID.String(),
		"email": "user@gmail.com",
	})
	ts.Require().NoError(err)
	ts.Require().NoError(ts.API.db.Create(identityB))

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	userData := &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    "user@gmail.com",
				Verified: true,
				Primary:  true,
			},
		},
		Metadata: &provider.Claims{
			Subject: "apple-sub-123",
		},
	}

	err = ts.API.db.Transaction(func(tx *storage.Connection) error {
		decision, resolvedUser, terr := ts.API.createAccountFromExternalIdentity(tx, req, userData, "apple", false)
		ts.Require().NoError(terr)
		ts.Equal(models.AccountExists, decision)
		ts.Equal(userA.ID, resolvedUser.ID)
		return nil
	})
	ts.Require().NoError(err)

	persistedIdentity, terr := models.FindIdentityByIdAndProvider(ts.API.db, "apple-sub-123", "apple")
	ts.Require().NoError(terr)
	ts.Equal("anon@privaterelay.appleid.com", persistedIdentity.IdentityData["email"].(string))
}


