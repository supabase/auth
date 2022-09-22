package docs

import (
	"github.com/netlify/gotrue/api"
)

// swagger:route GET /verify verify verify-get
// Verifies a sign up.

// swagger:parameters verify-get
type verifyGetParamsWrapper struct {
	// in:query
	api.VerifyParams
}

// swagger:route POST /verify verify verify-post
// Verifies a sign up.

// swagger:parameters verify-post
type verifyPostParamsWrapper struct {
	// in:body
	Body api.VerifyParams
}
