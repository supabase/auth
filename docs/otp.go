package docs

import "github.com/netlify/gotrue/api"

// swagger:route POST /otp otp otpPostParams
//
// Delivers a magiclink or sms otp to the user depending on whether the request body contains an "email" or "phone" field.
//
// responses:
//   200: otpResponse
//   401: httpErrorResponse
//   400: httpErrorResponse
//   404: httpErrorResponse
//   422: httpErrorResponse
//   500: httpErrorResponse

// User's email or phone number
// swagger:parameters otpPostParams
type otpPostParams struct {
	// in:body
	Body api.OtpParams
}

// Empty json object.
// swagger:response otpResponse
type otpResposne struct {
	// in:body
	Body struct{}
}
