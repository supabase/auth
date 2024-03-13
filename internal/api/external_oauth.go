package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/mrjones/oauth"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/observability"
)

// OAuthProviderData contains the userData and token returned by the oauth provider
type OAuthProviderData struct {
	userData     *provider.UserProvidedData
	token        string
	refreshToken string
	code         string
}

// loadFlowState parses the `state` query parameter as a JWS payload,
// extracting the provider requested
func (a *API) loadFlowState(w http.ResponseWriter, r *http.Request) (context.Context, error) {
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
	return a.loadExternalState(ctx, state)
}

func (a *API) oAuthCallback(ctx context.Context, r *http.Request, providerType string) (*OAuthProviderData, error) {
	var rq url.Values
	if err := r.ParseForm(); r.Method == http.MethodPost && err == nil {
		rq = r.Form
	} else {
		rq = r.URL.Query()
	}

	extError := rq.Get("error")
	if extError != "" {
		return nil, oauthError(extError, rq.Get("error_description"))
	}

	oauthCode := rq.Get("code")
	if oauthCode == "" {
		return nil, badRequestError(ErrorCodeBadOAuthCallback, "OAuth callback with missing authorization code missing")
	}

	oAuthProvider, err := a.OAuthProvider(ctx, providerType)
	if err != nil {
		return nil, badRequestError(ErrorCodeOAuthProviderNotSupported, "Unsupported provider: %+v", err).WithInternalError(err)
	}

	log := observability.GetLogEntry(r)
	log.WithFields(logrus.Fields{
		"provider": providerType,
		"code":     oauthCode,
	}).Debug("Exchanging oauth code")

	token, err := oAuthProvider.GetOAuthToken(oauthCode)
	if err != nil {
		return nil, internalServerError("Unable to exchange external code: %s", oauthCode).WithInternalError(err)
	}

	userData, err := oAuthProvider.GetUserData(ctx, token)
	if err != nil {
		return nil, internalServerError("Error getting user profile from external provider").WithInternalError(err)
	}

	switch externalProvider := oAuthProvider.(type) {
	case *provider.AppleProvider:
		// apple only returns user info the first time
		oauthUser := rq.Get("user")
		if oauthUser != "" {
			err := externalProvider.ParseUser(oauthUser, userData)
			if err != nil {
				return nil, err
			}
		}
	}

	return &OAuthProviderData{
		userData:     userData,
		token:        token.AccessToken,
		refreshToken: token.RefreshToken,
		code:         oauthCode,
	}, nil
}

func (a *API) oAuth1Callback(ctx context.Context, providerType string) (*OAuthProviderData, error) {
	oAuthProvider, err := a.OAuthProvider(ctx, providerType)
	if err != nil {
		return nil, badRequestError(ErrorCodeOAuthProviderNotSupported, "Unsupported provider: %+v", err).WithInternalError(err)
	}
	oauthToken := getRequestToken(ctx)
	oauthVerifier := getOAuthVerifier(ctx)
	var accessToken *oauth.AccessToken
	var userData *provider.UserProvidedData
	if twitterProvider, ok := oAuthProvider.(*provider.TwitterProvider); ok {
		accessToken, err = twitterProvider.Consumer.AuthorizeToken(&oauth.RequestToken{
			Token: oauthToken,
		}, oauthVerifier)
		if err != nil {
			return nil, internalServerError("Unable to retrieve access token").WithInternalError(err)
		}
		userData, err = twitterProvider.FetchUserData(ctx, accessToken)
		if err != nil {
			return nil, internalServerError("Error getting user email from external provider").WithInternalError(err)
		}
	}

	return &OAuthProviderData{
		userData:     userData,
		token:        accessToken.Token,
		refreshToken: "",
	}, nil

}

// OAuthProvider returns the corresponding oauth provider as an OAuthProvider interface
func (a *API) OAuthProvider(ctx context.Context, name string) (provider.OAuthProvider, error) {
	providerCandidate, err := a.Provider(ctx, name, "")
	if err != nil {
		return nil, err
	}

	switch p := providerCandidate.(type) {
	case provider.OAuthProvider:
		return p, nil
	default:
		return nil, fmt.Errorf("Provider %v cannot be used for OAuth", name)
	}
}
