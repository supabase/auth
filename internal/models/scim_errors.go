package models

import "errors"

type SCIMNotFoundError struct{}

func (e SCIMNotFoundError) Error() string {
	return "SCIM resource not found"
}

func (e SCIMNotFoundError) Is(target error) bool {
	return target == errNotFound
}

var (
	ErrSCIMTokenExpiry         = errors.New("SCIM token must expire after it is created")
	ErrSCIMStale               = errors.New("SCIM resource has changed since it was read")
	ErrSCIMUserConflict        = errors.New("SCIM user conflicts with an existing user")
	ErrSCIMUserLinked          = errors.New("user is already linked to a SCIM user in this provider")
	ErrSCIMUserDeleted         = errors.New("user was deleted by this provider")
	ErrSCIMGroupConflict       = errors.New("SCIM group conflicts with an existing group")
	ErrSCIMGroupMemberNotFound = errors.New("SCIM group member is not a user in this provider")
)
