package docs

// swagger:route GET /authorize oauth authorizeGetParams
//
// Get access_token from external oauth provider.
//
// Redirects to provider to start the OAuth1.0 or OAuth2.0 protocol.
//
// responses:
//   302: authorizeGetResponse
//   400: httpErrorResponse
//   404: httpErrorResponse
//   500: httpErrorResponse

// swagger:parameters authorizeGetParams
type authorizeGetParams struct {
	// Provider type
	//
	// in:query
	// required: true
	// enum: apple,azure,bitbucket,discord,facebook,github,gitlab,google,twitch,twitter
	Provider string `json:"provider"`

	// Oauth scopes (email and name are requested by default)
	//
	// in:query
	Scopes string `json:"scopes"`
}

// User redirected to external source
// swagger:response authorizeGetResponse
type authorizeGetResponse struct {
}
