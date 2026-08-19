package api

import (
	"fmt"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/models"
)

const (
	googleSyncOldEmail      = "google@example.com"
	googleSyncNewEmail      = "new@example.com"
	googleSyncTakenEmail    = "taken@example.com"
	googleSyncPersonalEmail = "personal@example.com"
	googleSyncWorkEmail     = "work@example.com"
	googleSyncProviderID    = "googleTestId"
)

func googleSyncUserJSON(email string, verified *bool) string {
	if email == "" {
		return `{"id":"googleTestId","name":"Google Test","picture":"http://example.com/avatar"}`
	}
	if verified == nil {
		return fmt.Sprintf(`{"id":"googleTestId","name":"Google Test","picture":"http://example.com/avatar","email":%q}`, email)
	}
	return fmt.Sprintf(`{"id":"googleTestId","name":"Google Test","picture":"http://example.com/avatar","email":%q,"verified_email":%v}`, email, *verified)
}

func boolPtr(v bool) *bool { return &v }

func (ts *ExternalTestSuite) performGoogleOAuth(userJSON string) {
	tokenCount, userCount := 0, 0
	server := GoogleTestSignupSetup(ts, &tokenCount, &userCount, "authcode", userJSON)
	defer server.Close()

	u := performAuthorization(ts, "google", "authcode", "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "Google Test", googleSyncProviderID, "http://example.com/avatar")
}

func (ts *ExternalTestSuite) loadGoogleUserAndIdentity() (*models.User, *models.Identity) {
	identity, err := models.FindIdentityByIdAndProvider(ts.API.db, googleSyncProviderID, GoogleProvider)
	require.NoError(ts.T(), err)
	user, err := models.FindUserByID(ts.API.db, identity.UserID)
	require.NoError(ts.T(), err)
	return user, identity
}

func (ts *ExternalTestSuite) assertGoogleIdentityStable(userID, identityID uuid.UUID, providerID string) {
	user, identity := ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), userID, user.ID)
	require.Equal(ts.T(), identityID, identity.ID)
	require.Equal(ts.T(), providerID, identity.ProviderID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailDisabledPreservesCanonicalEmail() {
	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncNewEmail, boolPtr(true)))
	user, identity = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	require.Equal(ts.T(), googleSyncNewEmail, identity.GetEmail())
	ts.assertGoogleIdentityStable(userID, identityID, providerID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailEnabledUpdatesOAuthOnlyUser() {
	ts.Config.External.Google.SyncEmail = true

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	_, err := models.FindIdentityByIdAndProvider(ts.API.db, user.ID.String(), EmailProvider)
	require.True(ts.T(), models.IsNotFoundError(err), "oauth-only users must not have an email identity")
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncNewEmail, boolPtr(true)))
	user, identity = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncNewEmail, user.GetEmail())
	require.Equal(ts.T(), googleSyncNewEmail, identity.GetEmail())
	ts.assertGoogleIdentityStable(userID, identityID, providerID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailSameAddressIsNoOp() {
	ts.Config.External.Google.SyncEmail = true

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	require.Equal(ts.T(), googleSyncOldEmail, identity.GetEmail())
	ts.assertGoogleIdentityStable(userID, identityID, providerID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailUnverifiedDoesNotUpdateCanonicalEmail() {
	ts.Config.External.Google.SyncEmail = true

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncNewEmail, boolPtr(false)))
	user, identity = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	require.Equal(ts.T(), googleSyncNewEmail, identity.GetEmail())
	ts.assertGoogleIdentityStable(userID, identityID, providerID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailMissingVerificationDoesNotUpdateCanonicalEmail() {
	ts.Config.External.Google.SyncEmail = true

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncNewEmail, nil))
	user, identity = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	require.Equal(ts.T(), googleSyncNewEmail, identity.GetEmail())
	ts.assertGoogleIdentityStable(userID, identityID, providerID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailMissingEmailDoesNotUpdateCanonicalEmail() {
	ts.Config.External.Google.SyncEmail = true
	ts.Config.External.Google.EmailOptional = true

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID

	ts.performGoogleOAuth(googleSyncUserJSON("", nil))
	user, identity = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	require.Equal(ts.T(), "", identity.GetEmail())
	ts.assertGoogleIdentityStable(userID, identityID, providerID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailIndependentEmailIdentityIsProtected() {
	ts.Config.External.Google.SyncEmail = true

	existing, err := ts.createUserWithIdentity(GoogleProvider, googleSyncProviderID, googleSyncPersonalEmail, "Google Test", "http://example.com/avatar", "")
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), existing.Confirm(ts.API.db))

	googleIdentity, err := models.FindIdentityByIdAndProvider(ts.API.db, googleSyncProviderID, GoogleProvider)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), googleIdentity.UpdateIdentityData(ts.API.db, map[string]interface{}{
		"sub":            googleSyncProviderID,
		"email":          googleSyncWorkEmail,
		"email_verified": true,
	}))

	ts.performGoogleOAuth(googleSyncUserJSON("new-work@example.com", boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), existing.ID, user.ID)
	require.Equal(ts.T(), googleIdentity.ID, identity.ID)
	require.Equal(ts.T(), googleSyncProviderID, identity.ProviderID)
	require.Equal(ts.T(), googleSyncPersonalEmail, user.GetEmail())
	require.Equal(ts.T(), "new-work@example.com", identity.GetEmail())
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailSameAddressEmailIdentityIsProtected() {
	ts.Config.External.Google.SyncEmail = true

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID

	emailIdentity, err := models.NewIdentity(user, EmailProvider, map[string]interface{}{
		"sub":            user.ID.String(),
		"email":          user.GetEmail(),
		"email_verified": true,
	})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(emailIdentity))

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncNewEmail, boolPtr(true)))
	user, identity = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	require.Equal(ts.T(), googleSyncNewEmail, identity.GetEmail())
	ts.assertGoogleIdentityStable(userID, identityID, providerID)

	kept, err := models.FindIdentityByIdAndProvider(ts.API.db, user.ID.String(), EmailProvider)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), googleSyncOldEmail, kept.GetEmail())
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailCollisionDoesNotMergeAccounts() {
	ts.Config.External.Google.SyncEmail = true

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	userA, identityA := ts.loadGoogleUserAndIdentity()
	userAID, identityAID, providerID := userA.ID, identityA.ID, identityA.ProviderID

	userB, err := ts.createUser("", googleSyncTakenEmail, "Other User", "", "")
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), userB.Confirm(ts.API.db))
	userBID := userB.ID
	bIdentities, err := models.FindIdentitiesByUserID(ts.API.db, userBID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), bIdentities, 1)

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncTakenEmail, boolPtr(true)))

	userA, identityA = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, userA.GetEmail())
	require.Equal(ts.T(), googleSyncTakenEmail, identityA.GetEmail())
	ts.assertGoogleIdentityStable(userAID, identityAID, providerID)

	userB, err = models.FindUserByID(ts.API.db, userBID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), googleSyncTakenEmail, userB.GetEmail())
	require.Equal(ts.T(), userBID, userB.ID)
	require.NotEqual(ts.T(), userA.ID, userB.ID)

	bIdentitiesAfter, err := models.FindIdentitiesByUserID(ts.API.db, userBID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), bIdentitiesAfter, 1)
	require.Equal(ts.T(), bIdentities[0].ID, bIdentitiesAfter[0].ID)
	require.Equal(ts.T(), EmailProvider, bIdentitiesAfter[0].Provider)

	aIdentities, err := models.FindIdentitiesByUserID(ts.API.db, userAID)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), aIdentities, 1)
	require.Equal(ts.T(), GoogleProvider, aIdentities[0].Provider)
	require.Equal(ts.T(), googleSyncProviderID, aIdentities[0].ProviderID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailCaseOnlyChangeIsNoOp() {
	ts.Config.External.Google.SyncEmail = true

	ts.performGoogleOAuth(googleSyncUserJSON(googleSyncOldEmail, boolPtr(true)))
	user, identity := ts.loadGoogleUserAndIdentity()
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID

	ts.performGoogleOAuth(googleSyncUserJSON("Google@Example.com", boolPtr(true)))
	user, identity = ts.loadGoogleUserAndIdentity()
	require.Equal(ts.T(), googleSyncOldEmail, user.GetEmail())
	require.Equal(ts.T(), googleSyncOldEmail, identity.GetEmail())
	ts.assertGoogleIdentityStable(userID, identityID, providerID)
}

func (ts *ExternalTestSuite) TestOAuthSyncEmailGitHubOAuthOnlyUser() {
	ts.Config.External.Github.SyncEmail = true

	oldEmails := `[{"email":"github@example.com", "primary": true, "verified": true}]`
	newEmails := `[{"email":"github-new@example.com", "primary": true, "verified": true}]`

	tokenCount, userCount := 0, 0
	server := GitHubTestSignupSetup(ts, &tokenCount, &userCount, "authcode", oldEmails)
	u := performAuthorization(ts, "github", "authcode", "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "github@example.com", "GitHub Test", "123", "http://example.com/avatar")
	server.Close()

	identity, err := models.FindIdentityByIdAndProvider(ts.API.db, "123", GitHubProvider)
	require.NoError(ts.T(), err)
	user, err := models.FindUserByID(ts.API.db, identity.UserID)
	require.NoError(ts.T(), err)
	userID, identityID, providerID := user.ID, identity.ID, identity.ProviderID
	require.Equal(ts.T(), "github@example.com", user.GetEmail())

	tokenCount, userCount = 0, 0
	server = GitHubTestSignupSetup(ts, &tokenCount, &userCount, "authcode", newEmails)
	defer server.Close()
	u = performAuthorization(ts, "github", "authcode", "")
	assertAuthorizationSuccess(ts, u, tokenCount, userCount, "", "GitHub Test", "123", "http://example.com/avatar")

	identity, err = models.FindIdentityByIdAndProvider(ts.API.db, "123", GitHubProvider)
	require.NoError(ts.T(), err)
	user, err = models.FindUserByID(ts.API.db, identity.UserID)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), "github-new@example.com", user.GetEmail())
	require.Equal(ts.T(), "github-new@example.com", identity.GetEmail())
	require.Equal(ts.T(), userID, user.ID)
	require.Equal(ts.T(), identityID, identity.ID)
	require.Equal(ts.T(), providerID, identity.ProviderID)
}

func TestOAuthVerifiedEmail(t *testing.T) {
	email, ok := oauthVerifiedEmail(&models.Identity{IdentityData: map[string]interface{}{
		"email":          "New@Example.com",
		"email_verified": true,
	}})
	require.True(t, ok)
	require.Equal(t, "new@example.com", email)

	_, ok = oauthVerifiedEmail(&models.Identity{IdentityData: map[string]interface{}{
		"email":          "new@example.com",
		"email_verified": false,
	}})
	require.False(t, ok)

	_, ok = oauthVerifiedEmail(&models.Identity{IdentityData: map[string]interface{}{
		"email": "new@example.com",
	}})
	require.False(t, ok)

	_, ok = oauthVerifiedEmail(&models.Identity{IdentityData: map[string]interface{}{
		"email_verified": true,
	}})
	require.False(t, ok)

	_, ok = oauthVerifiedEmail(&models.Identity{IdentityData: map[string]interface{}{
		"email":          "",
		"email_verified": true,
	}})
	require.False(t, ok)
}
