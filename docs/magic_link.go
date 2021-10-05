package docs

import (
	"github.com/netlify/gotrue/api"
)

// swagger:route POST /magiclink recover magiclinkPostParams
//
// Deliver link to user to redeem an access_token
//
// Magic Link will deliver a link (e.g. `/verify?type=magiclink&token=fgtyuf68ddqdaDd`) to the user based on email address which they can use to redeem an access_token.
// By default, magic links can only be sent once every 60 seconds
//
// responses:
//   200: recoverPostResponse
//   401: httpErrorResponse
//   400: httpErrorResponse
//   404: httpErrorResponse
//   422: httpErrorResponse
//   500: httpErrorResponse

// User's email
// swagger:parameters magiclinkPostParams
type magiclinkPostParams struct {
	// in:body
	Body api.MagicLinkParams
}

// Empty json object
// swagger:response magiclinkPostResponse
type magiclinkPostResponse struct {
	// in:body
	Body struct{}
}
