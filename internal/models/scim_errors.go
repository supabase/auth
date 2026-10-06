package models

import "errors"

type SCIMNotFoundError struct{}

func (e SCIMNotFoundError) Error() string {
	return "SCIM resource not found"
}

func (e SCIMNotFoundError) Is(target error) bool {
	return target == errNotFound
}

type SCIMUniquenessError struct{}

func (e SCIMUniquenessError) Error() string {
	return "SCIM resource must be unique"
}

func (e SCIMUniquenessError) Is(target error) bool {
	return target == errUniqueConstraintViolated
}

var ErrSCIMTokenExpiry = errors.New("SCIM token must expire after it is created")
