//lint:file-ignore U1000 ignore go-swagger template
package docs

// swagger:route GET /authorize oauth authorize
// Redirects the user to the 3rd-party OAuth provider to start the OAuth1.0 or OAuth2.0 authentication process.
// parameters:
// + name: redirect_to
//   in: query
//   description: The redirect url to return the user to after the `/callback` endpoint has completed.
//   required: false
// + name: hook_data
//   in: query
//   description: An opaque value passed through to the auth hooks invoked while serving this request, such as `before-user-created`. It is stored with the flow state for the duration of the provider round trip, cleared once consumed, not forwarded to the provider, and never stored on the user record. It travels in this URL, so it reaches browser history, referrer headers and proxy logs: it must not be a long-lived bearer secret, and a hook must validate what arrives rather than treat its presence as proof of anything. A reference the hook can check against its own records is the intended shape. Limited to 4096 bytes.
//   required: false
// responses:
//   302: authorizeResponse

// Redirects user to the 3rd-party OAuth provider
// swagger:response authorizeResponse
type authorizeResponseWrapper struct{}

// swagger:route GET /callback oauth callback
// Receives the redirect from an external provider during the OAuth authentication process. Starts the process of creating an access and refresh token.
// responses:
//   302: callbackResponse

// Redirects user to the redirect url specified in `/authorize`. If no `redirect_url` is provided, the user will be redirected to the `SITE_URL`.
// swagger:response callbackResponse
type callbackResponseWrapper struct{}
