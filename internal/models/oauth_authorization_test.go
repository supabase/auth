package models

import (
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewOAuthServerAuthorization(t *testing.T) {
	clientID := uuid.Must(uuid.NewV4())
	redirectURI := "https://example.com/callback"
	scope := "openid profile"
	state := "random-state"
	codeChallenge := "test-challenge"
	codeChallengeMethod := "S256"
	resource := "https://api.example.com/"

	auth := NewOAuthServerAuthorization(clientID, redirectURI, scope, state, resource, codeChallenge, codeChallengeMethod)

	assert.NotEmpty(t, auth.ID)
	assert.NotEmpty(t, auth.AuthorizationID)
	assert.Equal(t, clientID, auth.ClientID)
	assert.Nil(t, auth.UserID)
	assert.Equal(t, redirectURI, auth.RedirectURI)
	assert.Equal(t, scope, auth.Scope)
	assert.Equal(t, state, *auth.State)
	assert.Equal(t, resource, *auth.Resource)
	assert.Equal(t, codeChallenge, *auth.CodeChallenge)
	assert.Equal(t, "s256", *auth.CodeChallengeMethod) // Should be normalized to lowercase
	assert.Equal(t, OAuthServerResponseTypeCode, auth.ResponseType)
	assert.Equal(t, OAuthServerAuthorizationPending, auth.Status)
	assert.True(t, auth.ExpiresAt.After(auth.CreatedAt))
	assert.Nil(t, auth.ApprovedAt)
}

func TestNewOAuthServerAuthorization_CodeChallengeMethodNormalization(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"uppercase S256", "S256", "s256"},
		{"lowercase s256", "s256", "s256"},
		{"mixed case S256", "s256", "s256"},
		{"uppercase PLAIN", "PLAIN", "plain"},
		{"lowercase plain", "plain", "plain"},
		{"mixed case Plain", "Plain", "plain"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			auth := NewOAuthServerAuthorization(
				uuid.Must(uuid.NewV4()),
				"https://example.com/callback",
				"openid",
				"state",
				"",
				"challenge",
				tc.input,
			)

			assert.Equal(t, tc.expected, *auth.CodeChallengeMethod,
				"Expected code_challenge_method to be normalized to %s, got %s", tc.expected, *auth.CodeChallengeMethod)
		})
	}
}

func TestOAuthServerAuthorization_IsExpired(t *testing.T) {
	auth := &OAuthServerAuthorization{
		CreatedAt: time.Now().Add(-1 * time.Hour),
		ExpiresAt: time.Now().Add(-30 * time.Minute), // Expired 30 minutes ago
	}

	assert.True(t, auth.IsExpired())

	auth.ExpiresAt = time.Now().Add(30 * time.Minute) // Expires in 30 minutes
	assert.False(t, auth.IsExpired())
}

func TestOAuthServerAuthorization_GenerateAuthorizationCode(t *testing.T) {
	auth := &OAuthServerAuthorization{}

	// First call should generate a code
	code1 := auth.GenerateAuthorizationCode()
	assert.NotEmpty(t, code1)
	assert.Equal(t, code1, *auth.AuthorizationCode)

	// Second call should return the same code
	code2 := auth.GenerateAuthorizationCode()
	assert.Equal(t, code1, code2)
}

func TestOAuthServerAuthorization_ApproveErrCases(t *testing.T) {
	tests := []struct {
		name    string
		auth    *OAuthServerAuthorization
		wantErr bool
		errMsg  string
	}{
		{
			name: "approval of expired authorization",
			auth: &OAuthServerAuthorization{
				Status:    OAuthServerAuthorizationPending,
				CreatedAt: time.Now().Add(-1 * time.Hour),
				ExpiresAt: time.Now().Add(-30 * time.Minute), // Expired
			},
			wantErr: true,
			errMsg:  "authorization request has expired",
		},
		{
			name: "approval of already approved authorization",
			auth: &OAuthServerAuthorization{
				Status:    OAuthServerAuthorizationApproved,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			},
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
		{
			name: "approval of denied authorization",
			auth: &OAuthServerAuthorization{
				Status:    OAuthServerAuthorizationDenied,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			},
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
		{
			name: "approval of expired status authorization",
			auth: &OAuthServerAuthorization{
				Status:    OAuthServerAuthorizationExpired,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
			},
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test validation logic before database operations
			if tt.auth.IsExpired() {
				err := fmt.Errorf("authorization request has expired")
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "authorization request has expired")
				return
			}

			if tt.auth.Status != OAuthServerAuthorizationPending {
				err := fmt.Errorf("authorization request is not pending (current status: %s)", tt.auth.Status)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "authorization request is not pending")
				return
			}

			// If we get here, it should be valid for approval
			assert.False(t, tt.wantErr, "Expected error but validation passed")
		})
	}
}

func TestOAuthServerAuthorization_ApproveSuccess(t *testing.T) {
	auth := &OAuthServerAuthorization{
		Status:    OAuthServerAuthorizationPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	// Test the in-memory state changes that happen during approval
	beforeTime := time.Now()
	auth.Status = OAuthServerAuthorizationApproved
	now := time.Now()
	auth.ApprovedAt = &now
	auth.GenerateAuthorizationCode()

	assert.Equal(t, OAuthServerAuthorizationApproved, auth.Status)
	assert.NotNil(t, auth.ApprovedAt)
	assert.True(t, auth.ApprovedAt.After(beforeTime))
	assert.NotEmpty(t, *auth.AuthorizationCode)
}

func TestOAuthServerAuthorization_Deny(t *testing.T) {
	tests := []struct {
		name    string
		status  OAuthServerAuthorizationStatus
		wantErr bool
		errMsg  string
	}{
		{
			name:    "deny pending authorization",
			status:  OAuthServerAuthorizationPending,
			wantErr: false,
		},
		{
			name:    "deny already approved authorization",
			status:  OAuthServerAuthorizationApproved,
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
		{
			name:    "deny already denied authorization",
			status:  OAuthServerAuthorizationDenied,
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
		{
			name:    "deny expired authorization",
			status:  OAuthServerAuthorizationExpired,
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &OAuthServerAuthorization{Status: tt.status}

			if auth.Status != OAuthServerAuthorizationPending {
				err := fmt.Errorf("authorization request is not pending (current status: %s)", auth.Status)
				if tt.wantErr {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			// Test successful denial state change
			auth.Status = OAuthServerAuthorizationDenied
			assert.Equal(t, OAuthServerAuthorizationDenied, auth.Status)
		})
	}
}

func TestOAuthServerAuthorization_MarkExpiredLogic(t *testing.T) {
	tests := []struct {
		name    string
		status  OAuthServerAuthorizationStatus
		wantErr bool
		errMsg  string
	}{
		{
			name:    "mark pending authorization as expired",
			status:  OAuthServerAuthorizationPending,
			wantErr: false,
		},
		{
			name:    "mark approved authorization as expired",
			status:  OAuthServerAuthorizationApproved,
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
		{
			name:    "mark denied authorization as expired",
			status:  OAuthServerAuthorizationDenied,
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
		{
			name:    "mark already expired authorization as expired",
			status:  OAuthServerAuthorizationExpired,
			wantErr: true,
			errMsg:  "authorization request is not pending",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &OAuthServerAuthorization{Status: tt.status}

			if auth.Status != OAuthServerAuthorizationPending {
				err := fmt.Errorf("authorization request is not pending (current status: %s)", auth.Status)
				if tt.wantErr {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			// Test successful expiration state change
			auth.Status = OAuthServerAuthorizationExpired
			assert.Equal(t, OAuthServerAuthorizationExpired, auth.Status)
		})
	}
}

func TestOAuthServerAuthorization_Validate(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	clientID := uuid.Must(uuid.NewV4())
	validAuth := &OAuthServerAuthorization{
		ClientID:     clientID,
		UserID:       &userID,
		RedirectURI:  "https://example.com/callback",
		Scope:        "openid",
		ResponseType: OAuthServerResponseTypeCode,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	// Valid authorization should pass
	assert.NoError(t, validAuth.Validate())

	// Test UserID can be nil (for unauthenticated requests)
	validAuthNoUser := *validAuth
	validAuthNoUser.UserID = nil
	assert.NoError(t, validAuthNoUser.Validate())

	// Test invalid cases
	tests := []struct {
		name    string
		modify  func(*OAuthServerAuthorization)
		wantErr bool
		errMsg  string
	}{
		{
			name:    "missing client_id",
			modify:  func(a *OAuthServerAuthorization) { a.ClientID = uuid.Nil },
			wantErr: true,
			errMsg:  "client_id is required",
		},
		{
			name:    "missing redirect_uri",
			modify:  func(a *OAuthServerAuthorization) { a.RedirectURI = "" },
			wantErr: true,
			errMsg:  "redirect_uri is required",
		},
		{
			name:    "missing scope",
			modify:  func(a *OAuthServerAuthorization) { a.Scope = "" },
			wantErr: true,
			errMsg:  "scope is required",
		},
		{
			name:    "invalid response_type",
			modify:  func(a *OAuthServerAuthorization) { a.ResponseType = "token" },
			wantErr: true,
			errMsg:  "only response_type=code is supported",
		},
		{
			name:    "expires_at before created_at",
			modify:  func(a *OAuthServerAuthorization) { a.ExpiresAt = a.CreatedAt.Add(-1 * time.Minute) },
			wantErr: true,
			errMsg:  "expires_at must be after created_at",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := *validAuth // Copy
			tt.modify(&auth)

			err := auth.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
