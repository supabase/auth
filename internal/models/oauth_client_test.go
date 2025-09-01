package models

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
	"golang.org/x/crypto/bcrypt"
)

type OAuthServerClientTestSuite struct {
	suite.Suite
	db *storage.Connection
}

func (ts *OAuthServerClientTestSuite) SetupTest() {
	_ = TruncateAll(ts.db)
}

func TestOAuthServerClient(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &OAuthServerClientTestSuite{
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *OAuthServerClientTestSuite) TestOAuthServerClientValidation() {
	testClientName := "Test Client"
	testSecretHash, _ := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	validClient := &OAuthServerClient{
		ID:               uuid.Must(uuid.NewV4()),
		ClientID:         "test_client_id",
		ClientName:       &testClientName,
		RegistrationType: "dynamic",
		ClientType:       OAuthServerClientTypeConfidential,
		ClientSecretHash: string(testSecretHash),
		RedirectURIs:     "https://example.com/callback",
		GrantTypes:       "authorization_code,refresh_token",
	}

	// Test valid client
	err := validClient.Validate()
	assert.NoError(ts.T(), err)

	// Test missing client_id
	invalidClient := *validClient
	invalidClient.ClientID = ""
	err = invalidClient.Validate()
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "client_id is required")

	// Test missing client_id
	invalidClient = *validClient
	invalidClient.ClientID = ""
	err = invalidClient.Validate()
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "client_id is required")

	// Test invalid registration type
	invalidClient = *validClient
	invalidClient.RegistrationType = "invalid"
	err = invalidClient.Validate()
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "registration_type must be 'dynamic' or 'manual'")

	// Test missing redirect URIs
	invalidClient = *validClient
	invalidClient.RedirectURIs = ""
	err = invalidClient.Validate()
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "at least one redirect_uri is required")
}

func (ts *OAuthServerClientTestSuite) TestRedirectURIValidation() {
	validURIs := []string{
		"https://example.com/callback",
		"https://app.example.com/auth/callback",
		"http://localhost:3000/callback",
		"http://127.0.0.1:8080/auth",
	}

	invalidURIs := []string{
		"",                                  // empty
		"not-a-url",                         // not a URL
		"example.com/callback",              // missing scheme
		"ftp://example.com/callback",        // invalid scheme
		"https://example.com/callback#hash", // has fragment
		"http://example.com/callback",       // HTTP for non-localhost
	}

	// Test valid URIs
	for _, uri := range validURIs {
		err := validateRedirectURI(uri)
		assert.NoError(ts.T(), err, "URI should be valid: %s", uri)
	}

	// Test invalid URIs
	for _, uri := range invalidURIs {
		err := validateRedirectURI(uri)
		assert.Error(ts.T(), err, "URI should be invalid: %s", uri)
	}
}

func (ts *OAuthServerClientTestSuite) TestRedirectURIHelpers() {
	client := &OAuthServerClient{}

	// Test setting and getting redirect URIs
	uris := []string{
		"https://example.com/callback",
		"https://app.example.com/auth",
		"http://localhost:3000/callback",
	}

	client.SetRedirectURIs(uris)
	assert.Equal(ts.T(), "https://example.com/callback,https://app.example.com/auth,http://localhost:3000/callback", client.RedirectURIs)

	retrievedURIs := client.GetRedirectURIs()
	assert.Equal(ts.T(), uris, retrievedURIs)

	// Test empty URIs
	client.SetRedirectURIs([]string{})
	assert.Equal(ts.T(), "", client.RedirectURIs)

	retrievedURIs = client.GetRedirectURIs()
	assert.Equal(ts.T(), []string{}, retrievedURIs)

	// Test getting URIs from empty string
	client.RedirectURIs = ""
	retrievedURIs = client.GetRedirectURIs()
	assert.Equal(ts.T(), []string{}, retrievedURIs)
}

func (ts *OAuthServerClientTestSuite) TestCreateOAuthServerClient() {
	testAppName := "Test Application"
	testSecretHash, _ := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	client := &OAuthServerClient{
		ClientID:         "test_client_create_" + uuid.Must(uuid.NewV4()).String()[:8],
		ClientName:       &testAppName,
		GrantTypes:       "authorization_code,refresh_token",
		RegistrationType: "dynamic",
		ClientType:       OAuthServerClientTypeConfidential,
		ClientSecretHash: string(testSecretHash),
		RedirectURIs:     "https://example.com/callback",
	}

	err := CreateOAuthServerClient(ts.db, client)
	require.NoError(ts.T(), err)

	// Verify client was created with generated ID and timestamps
	assert.NotEqual(ts.T(), uuid.Nil, client.ID)
	assert.NotZero(ts.T(), client.CreatedAt)
	assert.NotZero(ts.T(), client.UpdatedAt)
}

func (ts *OAuthServerClientTestSuite) TestCreateOAuthServerClientValidation() {
	invalidClient := &OAuthServerClient{
		ClientID: "", // Missing required field
	}

	err := CreateOAuthServerClient(ts.db, invalidClient)
	assert.Error(ts.T(), err)
	assert.Contains(ts.T(), err.Error(), "client_id is required")
}

func (ts *OAuthServerClientTestSuite) TestFindOAuthServerClientByID() {
	// Create a test client
	testName := "Find By ID Test"
	testSecretHash, _ := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	client := &OAuthServerClient{
		ClientID:         "test_client_find_by_id_" + uuid.Must(uuid.NewV4()).String()[:8],
		ClientName:       &testName,
		GrantTypes:       "authorization_code,refresh_token",
		RegistrationType: "dynamic",
		ClientType:       OAuthServerClientTypeConfidential,
		ClientSecretHash: string(testSecretHash),
		RedirectURIs:     "https://example.com/callback",
	}

	err := CreateOAuthServerClient(ts.db, client)
	require.NoError(ts.T(), err)

	// Find by ID
	foundClient, err := FindOAuthServerClientByID(ts.db, client.ID)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), client.ClientID, foundClient.ClientID)
	assert.Equal(ts.T(), *client.ClientName, *foundClient.ClientName)

	// Test not found
	_, err = FindOAuthServerClientByID(ts.db, uuid.Must(uuid.NewV4()))
	assert.Error(ts.T(), err)
	assert.True(ts.T(), IsNotFoundError(err))
}

func (ts *OAuthServerClientTestSuite) TestFindOAuthServerClientByClientID() {
	// Create a test client
	testName := "Find By Client ID Test"
	testSecretHash, _ := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	client := &OAuthServerClient{
		ClientID:         "test_client_find_by_client_id_" + uuid.Must(uuid.NewV4()).String()[:8],
		ClientName:       &testName,
		GrantTypes:       "authorization_code,refresh_token",
		RegistrationType: "manual",
		ClientType:       OAuthServerClientTypeConfidential,
		ClientSecretHash: string(testSecretHash),
		RedirectURIs:     "https://example.com/callback",
	}

	err := CreateOAuthServerClient(ts.db, client)
	require.NoError(ts.T(), err)

	// Find by client_id
	foundClient, err := FindOAuthServerClientByClientID(ts.db, client.ClientID)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), client.ID, foundClient.ID)
	assert.Equal(ts.T(), *client.ClientName, *foundClient.ClientName)

	// Test not found
	_, err = FindOAuthServerClientByClientID(ts.db, "nonexistent_client_id")
	assert.Error(ts.T(), err)
	assert.True(ts.T(), IsNotFoundError(err))
}

func (ts *OAuthServerClientTestSuite) TestUpdateOAuthServerClient() {
	// Create a test client
	originalName := "Original Name"
	testSecretHash, _ := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	client := &OAuthServerClient{
		ClientID:         "test_client_update_" + uuid.Must(uuid.NewV4()).String()[:8],
		ClientName:       &originalName,
		GrantTypes:       "authorization_code,refresh_token",
		RegistrationType: "dynamic",
		ClientType:       OAuthServerClientTypeConfidential,
		ClientSecretHash: string(testSecretHash),
		RedirectURIs:     "https://example.com/callback",
	}

	err := CreateOAuthServerClient(ts.db, client)
	require.NoError(ts.T(), err)
	originalUpdatedAt := client.UpdatedAt

	// Update the client
	updatedName := "Updated Name"
	client.ClientName = &updatedName
	// client.Description removed - no longer exists
	client.SetRedirectURIs([]string{"https://updated.example.com/callback"})

	err = UpdateOAuthServerClient(ts.db, client)
	require.NoError(ts.T(), err)

	// Verify updates
	updatedClient, err := FindOAuthServerClientByID(ts.db, client.ID)
	require.NoError(ts.T(), err)
	assert.Equal(ts.T(), "Updated Name", *updatedClient.ClientName)
	// assert.Equal(ts.T(), "Updated description", updatedClient.Description.String()) // Description field removed
	assert.Equal(ts.T(), []string{"https://updated.example.com/callback"}, updatedClient.GetRedirectURIs())
	assert.True(ts.T(), updatedClient.UpdatedAt.After(originalUpdatedAt))
}

func (ts *OAuthServerClientTestSuite) TestClientSecretHashing() {
	// Test that secrets can be properly hashed and validated
	secret := "super_secret_client_secret"

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	require.NoError(ts.T(), err)

	// Test correct secret validates
	err = bcrypt.CompareHashAndPassword(hash, []byte(secret))
	assert.NoError(ts.T(), err)

	// Test incorrect secret fails
	err = bcrypt.CompareHashAndPassword(hash, []byte("wrong_secret"))
	assert.Error(ts.T(), err)
}

func (ts *OAuthServerClientTestSuite) TestSoftDelete() {
	// Create a test client
	testName := "Soft Delete Test"
	testSecretHash, _ := bcrypt.GenerateFromPassword([]byte("test_secret"), bcrypt.DefaultCost)
	client := &OAuthServerClient{
		ClientID:         "test_client_soft_delete_" + uuid.Must(uuid.NewV4()).String()[:8],
		ClientName:       &testName,
		GrantTypes:       "authorization_code,refresh_token",
		RegistrationType: "dynamic",
		ClientType:       OAuthServerClientTypeConfidential,
		ClientSecretHash: string(testSecretHash),
		RedirectURIs:     "https://example.com/callback",
	}

	err := CreateOAuthServerClient(ts.db, client)
	require.NoError(ts.T(), err)

	// Soft delete by setting deleted_at
	now := time.Now()
	client.DeletedAt = &now

	err = UpdateOAuthServerClient(ts.db, client)
	require.NoError(ts.T(), err)

	// Verify client is not found in normal queries (which filter out deleted)
	_, err = FindOAuthServerClientByClientID(ts.db, client.ClientID)
	assert.Error(ts.T(), err)
	assert.True(ts.T(), IsNotFoundError(err))
}
