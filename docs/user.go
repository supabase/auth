package docs

import (
	"github.com/netlify/gotrue/api"
	"github.com/netlify/gotrue/models"
)

// swagger:route GET /user user user-get
// Get information for the logged-in user.
// security:
//   - bearer:
// responses:
//   200: userResponse
// 	 401: unauthorizedError

// The current user.
// swagger:response userResponse
type userResponseWrapper struct {
	// in:body
	Body models.User
}

// swagger:route PUT /user user user-put
// Returns the updated user.
// security:
//   - bearer:
// responses:
//   200: userResponse
// 	 401: unauthorizedError

// The current user.
// swagger:parameters user-put
type userUpdateParams struct {
	// in:body
	Body api.UserUpdateParams
}
