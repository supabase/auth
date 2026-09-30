package api

import (
	"errors"
	"net/http"

	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
)

func scimError(err error) error {
	switch {
	case models.IsNotFoundError(err):
		return errSCIMNotFound()
	case models.IsStaleError(err):
		return errSCIMStale()
	case errors.Is(err, models.SCIMGroupConflictError{}):
		return scimerrors.ErrUniqueness(`"externalId" must be unique`)
	case errors.As(err, &models.SCIMGroupMemberNotFoundError{}):
		return errSCIMMemberNotFound()
	case errors.Is(err, models.SCIMUserConflictError{}):
		return scimerrors.ErrUniqueness(`"userName" and "externalId" must be unique`)
	case errors.Is(err, models.SCIMUserLinkedError{}):
		return scimerrors.ErrUniqueness("user is already provisioned by this provider")
	case errors.Is(err, models.SCIMUserDeletedError{}):
		return scimerrors.ErrUniqueness("user was deleted by this provider")
	}
	return err
}

func errSCIMNotFound() error {
	return scimerrors.ErrNotFound("resource not found")
}

func errSCIMStale() error {
	return scimerrors.ErrPreconditionFailed("resource has changed on the server")
}

func errSCIMMemberNotFound() error {
	return scimerrors.ErrInvalidValue(`"members.value" must reference a User in this provider`)
}

func errSCIMEmailRequired() error {
	return scimerrors.ErrInvalidValue(`"emails" or an email address "userName" is required`)
}

func errSCIMEmailInvalid() error {
	return scimerrors.ErrInvalidValue(`"emails" value must be an email address`)
}

func errSCIMTooManyRequests() error {
	return scimerrors.NewError(http.StatusTooManyRequests, "", "Request rate limit reached")
}

func scimHookError(err error) error {
	var httpErr *apierrors.HTTPError
	if errors.As(err, &httpErr) && httpErr.HTTPStatus < http.StatusInternalServerError {
		return scimerrors.NewError(httpErr.HTTPStatus, "", httpErr.Message)
	}
	return err
}
