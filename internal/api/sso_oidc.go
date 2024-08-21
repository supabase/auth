package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// GenerateRandomState generates a random state string for OAuth2
func GenerateRandomState(length int) (string, error) {
	// Create a byte slice to hold the random bytes
	bytes := make([]byte, length)

	// Read random bytes into the slice
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Encode the random bytes into a URL-safe base64 string
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func GenerateRedirectWithOIDC(a *API, db *storage.Connection, ssoProvider *models.SSOProvider, flowStateID *uuid.UUID, params *SingleSignOnParams) (*url.URL, error) {
	oidcProviderConfig, err := ssoProvider.OIDCProvider.GenericProviderConfig()
	if err != nil {
		return &url.URL{}, internalServerError("Error creating generic OIDC provider config").WithInternalError(err)
	}

	oidcProviderConfig.RedirectURI = fmt.Sprintf("%s/sso/oidc/callback", a.config.API.ExternalURL)

	provider, err := provider.NewGenericProvider(oidcProviderConfig, "openid")
	if err != nil {
		return &url.URL{}, internalServerError("Error creating generic OIDC provider").WithInternalError(err)
	}

	state, err := GenerateRandomState(32)
	if err != nil {
		return &url.URL{}, internalServerError("Error creating state").WithInternalError(err)
	}

	relayState := models.OIDCFlowState{
		SSOProviderID: ssoProvider.ID,
		State:         state,
		RedirectTo:    params.RedirectTo,
		FlowStateID:   flowStateID,
	}

	if err := db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(&relayState); terr != nil {
			return internalServerError("Error creating SAML relay state from sign up").WithInternalError(err)
		}

		return nil
	}); err != nil {
		return &url.URL{}, err
	}

	link := provider.AuthCodeURL(state)

	parsedUrl, err := url.Parse(link)
	if err != nil {
		return &url.URL{}, internalServerError("Error creating generic auth URL").WithInternalError(err)
	}

	return parsedUrl, nil
}

// loadFlowState parses the `state` query parameter as a JWS payload,
// extracting the provider requested
func (a *API) loadSSOOIDCFlowState(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	var state string
	if r.Method == http.MethodPost {
		state = r.FormValue("state")
	} else {
		state = r.URL.Query().Get("state")
	}

	if state == "" {
		return nil, badRequestError(ErrorCodeBadOAuthCallback, "OAuth state parameter missing")
	}

	ctx := r.Context()
	oauthToken := r.URL.Query().Get("oauth_token")
	if oauthToken != "" {
		ctx = withRequestToken(ctx, oauthToken)
	}
	oauthVerifier := r.URL.Query().Get("oauth_verifier")
	if oauthVerifier != "" {
		ctx = withOAuthVerifier(ctx, oauthVerifier)
	}
	return a.loadSSOIDCState(ctx, state)
}

func (a *API) loadSSOIDCState(ctx context.Context, state string) (context.Context, error) {
	db := a.db.WithContext(ctx)

	flowState, err := models.FindOIDCFlowStateByID(db, state)
	if err != nil {
		return nil, badRequestError(ErrorCodeBadOAuthState, "OAuth callback with invalid state").WithInternalError(err)
	}

	ctx = withFlowStateID(ctx, flowState.FlowStateID.String())

	ssoProvider, err := models.FindSSOProviderByID(db, flowState.SSOProviderID)
	if err != nil {
		return nil, badRequestError(ErrorCodeBadOAuthState, "OAuth callback provider not found").WithInternalError(err)
	}
	config, err := ssoProvider.OIDCProvider.GenericProviderConfig()

	config.RedirectURI = fmt.Sprintf("%s/sso/oidc/callback", a.config.API.ExternalURL)

	ctx = withGenericProviderConfig(ctx, &config)
	ctx = withExternalProviderType(ctx, "sso/oidc")

	return ctx, err
}
