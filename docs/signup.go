package docs

import (
	"github.com/netlify/gotrue/api"
)

// swagger:route POST /signup signup signup
// Password-based signup with either email or phone.
// responses:
//   200: userResponse

// swagger:parameters signup
type signupParamsWrapper struct {
	// in:body
	Body api.SignupParams
}
