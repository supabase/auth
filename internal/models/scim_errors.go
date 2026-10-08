package models

import "errors"

type SCIMNotFoundError struct{}

func (e SCIMNotFoundError) Error() string {
	return "SCIM resource not found"
}

func (e SCIMNotFoundError) Is(target error) bool {
	return target == errNotFound
}

var ErrSCIMTokenExpiry = errors.New("SCIM token must expire after it is created")
