package docs

// swagger:route GET /callback oauth callbackGetParams
//
// External provider should redirect to here
//
// Start procedure of creating token
//
// responses:
//   302: callbackGetResponse
//   400: httpErrorResponse
//   404: httpErrorResponse
//   500: httpErrorResponse

// swagger:parameters callbackGetParams
type callbackGetParams struct {
	// Error message
	//
	// in:query
	Error string `json:"error"`

	// State set by OAuth1.0 or OAuth2.0 provider
	//
	// in:query
	State string `json:"state"`

	// OAuth Token set by OAuth1.0 provider
	//
	// in:query
	OAuthToken string `json:"oauth_token"`

	// OAuth Verifier set by OAuth1.0 provider
	//
	// in:query
	OAuthVerifier string `json:"oauth_verifier"`
}

// User redirected to GOTRUE_SITE_URL with query parameters splitted by #
// swagger:response authorizeGetResponse
type callbackGetResponse struct {
	// in: query
	// required: true
	AccessToken string `json:"access_token"`
	// in: query
	// required: true
	RefreshToken string `json:"refresh_token"`
	// in: query
	// required: true
	ExpiresIn string `json:"expires_in"`
	// in: query
	// required: true
	Provider string `json:"provider"`
}
