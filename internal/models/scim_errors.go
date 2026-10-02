package models

import "github.com/gofrs/uuid"

type SCIMNotFoundError struct{}

func (e SCIMNotFoundError) Error() string {
	return "SCIM resource not found"
}

func (e SCIMNotFoundError) Is(target error) bool {
	return target == errNotFound
}

type SCIMTokenExpiryError struct{}

func (e SCIMTokenExpiryError) Error() string {
	return "SCIM token must expire after it is created"
}

type SCIMStaleError struct{}

func (e SCIMStaleError) Error() string {
	return "SCIM resource has changed since it was read"
}

type SCIMUserConflictError struct{}

func (e SCIMUserConflictError) Error() string {
	return "SCIM user conflicts with an existing user"
}

type SCIMUserLinkedError struct{}

func (e SCIMUserLinkedError) Error() string {
	return "user is already linked to a SCIM user in this provider"
}

type SCIMUserDeletedError struct{}

func (e SCIMUserDeletedError) Error() string {
	return "user was deleted by this provider"
}

type SCIMGroupConflictError struct{}

func (e SCIMGroupConflictError) Error() string {
	return "SCIM group conflicts with an existing group"
}

type SCIMGroupMemberNotFoundError struct {
	IDs []uuid.UUID
}

func (e SCIMGroupMemberNotFoundError) Error() string {
	return "SCIM group member is not a user in this provider"
}
