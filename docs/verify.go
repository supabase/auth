package docs

import "github.com/netlify/gotrue/api"

// swagger:route GET /verify recover verifyGetParams
//
// Verify a registration or a password recovery with redirect.
//
// Verify a registration or a password recovery and then redirect to app. Type can be `signup` or `recovery` and the `token` is a token returned from either `/signup` or `/recover`.
//
// responses:
//   301: verifyGetResponse
//   400: httpErrorResponse
//   404: httpErrorResponse
//   422: httpErrorResponse
//   500: httpErrorResponse

// swagger:parameters verifyGetParams
type verifyGetParams struct {
	// verification type

	// in:query
	// required: true
	// enum: signup,recovery,magiclink
	Type string `json:"type"`

	// user's token
	//
	// in:query
	// required: true
	Token string `json:"token"`

	// required for signup verification if no existing password exists
	//
	// in:query
	Password string `json:"password"`

	// required only `redirect_url` is different from `site_url`
	//
	// in:query
	RedirectTo string `json:"redirect_to"`
}

// Loged in and redirected to user's app with fields
// swagger:response verifyGetResponse
type verifyGetResponse struct {
	// in: query
	// required: true
	Token string `json:"access_token"`

	// in: query
	// required: true
	TokenType string `json:"token_type"`

	// in: query
	// required: true
	ExpiresIn int `json:"expires_in"`

	// in: query
	// required: true
	RefreshToken string `json:"refresh_token"`
}

// swagger:route POST /verify recover verifyPostParams
//
// Verify a registration or a password recovery.
//
// Verify an invite or email change link or sms otp.
// Type can be `invite` or `email_change` or `sms`.
//
// responses:
//   200: verifyPostResponse
//   400: httpErrorResponse
//   401: httpErrorResponse
//   404: httpErrorResponse
//   422: httpErrorResponse
//   500: httpErrorResponse

// swagger:parameters verifyPostParams
type verifyPostParams struct {
	// in: body
	Body struct {
		// verification type
		//
		// required: true
		Type string `json:"type"`
		// user's token or sms otp
		//
		// required: true
		Token string `json:"token"`

		// required only when type = `phone`
		Phone string `json:"phone"`

		// required for signup verification if no existing password exists
		Password string `json:"password"`

		// required only `redirect_url` is different from `site_url`
		RedirectTo string `json:"redirect_to"`
	}
}

// Successfully updated user info
// swagger:response verifyPostResponse
type verifyPostResponse struct {
	// swagger:allOf
	Body struct {
		api.AccessTokenResponse
	}
}
