package siwk

import (
	"errors"
	"fmt"
)

// Static errors
var (
	ErrMessageTooShort          = errors.New("siwk: message needs at least 6 lines")
	ErrInvalidHeader            = errors.New("siwk: message first line does not end in \" wants you to sign in with your Kaspa account:\"")
	ErrInvalidDomain            = errors.New("siwk: domain in first line of message is not valid")
	ErrInvalidAddress           = errors.New("siwk: wallet address is not a valid Kaspa address")
	ErrThirdLineNotEmpty        = errors.New("siwk: third line must be empty")
	ErrInvalidURI               = errors.New("siwk: URI is not valid")
	ErrInvalidIssuedAt          = errors.New("siwk: Issued At is not a valid ISO8601 timestamp")
	ErrInvalidExpirationTime    = errors.New("siwk: Expiration Time is not a valid ISO8601 timestamp")
	ErrInvalidNotBefore         = errors.New("siwk: Not Before is not a valid ISO8601 timestamp")
	ErrMissingURI               = errors.New("siwk: URI is not specified")
	ErrMissingIssuedAt          = errors.New("siwk: Issued At is not specified")
	ErrIssuedAfterExpiration    = errors.New("siwk: Issued At is after Expiration Time")
	ErrNotBeforeAfterExpiration = errors.New("siwk: Not Before is after Expiration Time")
	ErrInvalidNetworkID         = errors.New("siwk: Network ID is not valid")
)

// Dynamic error constructors
func errUnparsableLine(index int) error {
	return fmt.Errorf("siwk: encountered unparsable line at index %d", index)
}

func errUnsupportedVersion(got string) error {
	return fmt.Errorf("siwk: Version value is not supported, expected 0 or 1 got %q", got)
}

func errInvalidResource(position int) error {
	return fmt.Errorf("siwk: Resource at position %d has invalid URI", position)
}
