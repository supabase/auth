//lint:file-ignore U1000 ignore go-swagger template
package docs

import (
	"github.com/supabase/auth/internal/api"
)

// swagger:route POST /passkeys/sign-in user passkeySignIn
// Begin a passkey sign-in challenge.
// responses:
//   200: PasskeySignInChallengeResponse
//   400: BadRequestResponse
//   429: RateLimitResponse

type passkeySignInParamsWrapper struct {
	// in:body
	Body api.PasskeySignInRequest
}

// swagger:route POST /passkeys/sign-in/verify user passkeySignInVerify
// Complete a passkey sign-in challenge.
// responses:
//   200: AccessTokenResponseSchema
//   400: BadRequestResponse
//   429: RateLimitResponse

type passkeySignInVerifyParamsWrapper struct {
	// in:body
	Body api.PasskeySignInVerifyRequest
}

// swagger:route POST /passkeys user passkeyRegister
// Begin passkey registration for the authenticated user.
// responses:
//   200: PasskeyRegistrationResponse
//   400: BadRequestResponse
//   429: RateLimitResponse

type passkeyRegisterParamsWrapper struct {
	// in:body
	Body api.PasskeyRegistrationRequest
}

// swagger:route POST /passkeys/{passkey_id}/verify user passkeyVerify
// Verify a passkey registration challenge.
// responses:
//   200: PasskeyVerifyResponse
//   400: BadRequestResponse
//   429: RateLimitResponse

type passkeyVerifyParamsWrapper struct {
	// in:body
	Body api.PasskeyVerifyRequest
}
