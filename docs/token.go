package docs

import "github.com/netlify/gotrue/api"

// swagger:route POST /token token tokenPostParams
//
// This is an OAuth2 endpoint that currently implements the password and refresh_token grant types.
//
// This is an OAuth2 endpoint that currently implements the password and refresh_token grant types. Once you have an access token, you can access the methods requiring authentication by settings the `Authorization: Bearer YOUR_ACCESS_TOKEN_HERE` header.
//
// responses:
//   200: tokenPostResponse
//   400: httpErrorResponse
//   404: httpErrorResponse
//   422: httpErrorResponse
//   500: httpErrorResponse

// swagger:parameters tokenPostParams
type tokenPostParams struct {
	// specific verification type
	//
	// in:query
	// required: true
	// enum: password,refresh_token
	Type string `json:"grant_type"`

	// Provided info by user.
	// If using the password grant type, the email and password or phone and password fields are required.
	// If using the refresh_token grant type, the refresh_token field is required.
	// required: true
	// in: body
	Body struct {
		api.PasswordGrantParams
		api.RefreshTokenGrantParams
	}
}

// Get new token or refresh the old one
// swagger:response tokenPostResponse
type tokenPostResponse struct {
	// swagger: allOf
	Body struct {
		api.AccessTokenResponse
	}
}
