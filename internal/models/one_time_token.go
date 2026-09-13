package models

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/storage"
)

type OneTimeTokenType int

const (
	ConfirmationToken OneTimeTokenType = iota
	ReauthenticationToken
	RecoveryToken
	EmailChangeTokenNew
	EmailChangeTokenCurrent
	PhoneChangeToken
)

func (t OneTimeTokenType) String() string {
	switch t {
	case ConfirmationToken:
		return "confirmation_token"

	case ReauthenticationToken:
		return "reauthentication_token"

	case RecoveryToken:
		return "recovery_token"

	case EmailChangeTokenNew:
		return "email_change_token_new"

	case EmailChangeTokenCurrent:
		return "email_change_token_current"

	case PhoneChangeToken:
		return "phone_change_token"

	default:
		panic("OneTimeToken: unreachable case")
	}
}

func ParseOneTimeTokenType(s string) (OneTimeTokenType, error) {
	switch s {
	case "confirmation_token":
		return ConfirmationToken, nil

	case "reauthentication_token":
		return ReauthenticationToken, nil

	case "recovery_token":
		return RecoveryToken, nil

	case "email_change_token_new":
		return EmailChangeTokenNew, nil

	case "email_change_token_current":
		return EmailChangeTokenCurrent, nil

	case "phone_change_token":
		return PhoneChangeToken, nil

	default:
		return 0, fmt.Errorf("OneTimeTokenType: unrecognized string %q", s)
	}
}

func (t OneTimeTokenType) Value() (driver.Value, error) {
	return t.String(), nil
}

func (t *OneTimeTokenType) Scan(src interface{}) error {
	s, ok := src.(string)
	if !ok {
		return fmt.Errorf("OneTimeTokenType: scan type is not string but is %T", src)
	}

	parsed, err := ParseOneTimeTokenType(s)
	if err != nil {
		return err
	}

	*t = parsed
	return nil
}

type OneTimeTokenNotFoundError struct {
}

func (e OneTimeTokenNotFoundError) Error() string {
	return "One-time token not found"
}

func (e OneTimeTokenNotFoundError) Is(target error) bool {
	return target == errNotFound
}

type OneTimeToken struct {
	ID uuid.UUID `json:"id" db:"id"`

	UserID    uuid.UUID        `json:"user_id" db:"user_id"`
	TokenType OneTimeTokenType `json:"token_type" db:"token_type"`

	TokenHash string `json:"token_hash" db:"token_hash"`
	RelatesTo string `json:"relates_to" db:"relates_to"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

func (OneTimeToken) TableName() string {
	return "one_time_tokens"
}

func ClearAllOneTimeTokensForUser(tx *storage.Connection, userID uuid.UUID) error {
	return tx.Q().Where("user_id = ?", userID).Delete(OneTimeToken{})
}

func ClearOneTimeTokenForUser(tx *storage.Connection, userID uuid.UUID, tokenType OneTimeTokenType) error {
	if err := tx.Q().Where("token_type = ? and user_id = ?", tokenType, userID).Delete(OneTimeToken{}); err != nil {
		return err
	}

	return nil
}

func CreateOneTimeToken(tx *storage.Connection, userID uuid.UUID, relatesTo, tokenHash string, tokenType OneTimeTokenType) error {
	if err := ClearOneTimeTokenForUser(tx, userID, tokenType); err != nil {
		return err
	}

	oneTimeToken := &OneTimeToken{
		ID:        uuid.Must(uuid.NewV4()),
		UserID:    userID,
		TokenType: tokenType,
		TokenHash: tokenHash,
		RelatesTo: strings.ToLower(relatesTo),
	}

	if err := tx.Eager().Create(oneTimeToken); err != nil {
		return err
	}

	return nil
}

func FindOneTimeToken(tx *storage.Connection, tokenHash string, tokenTypes ...OneTimeTokenType) (*OneTimeToken, error) {
	oneTimeToken := &OneTimeToken{}

	query := tx.Eager().Q()

	switch len(tokenTypes) {
	case 2:
		query = query.Where("(token_type = ? or token_type = ?) and token_hash = ?", tokenTypes[0], tokenTypes[1], tokenHash) // #nosec G602

	case 1:
		query = query.Where("token_type = ? and token_hash = ?", tokenTypes[0], tokenHash)

	default:
		panic("at most 2 token types are accepted")
	}

	if err := query.First(oneTimeToken); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, OneTimeTokenNotFoundError{}
		}

		return nil, errors.Wrap(err, "error finding one time token")
	}

	return oneTimeToken, nil
}

// FindUserByOneTimeToken finds the user holding the one-time token matching
// tokenHash for any of the given token types.
func FindUserByOneTimeToken(tx *storage.Connection, tokenHash string, tokenTypes ...OneTimeTokenType) (*User, error) {
	ott, err := FindOneTimeToken(tx, tokenHash, tokenTypes...)
	if err != nil {
		return nil, err
	}

	return FindUserByID(tx, ott.UserID)
}

// FindUserByEmailChangeCurrentAndAudience finds a user with the matching email change and audience.
func FindUserByEmailChangeCurrentAndAudience(tx *storage.Connection, email, token, aud string) (*User, error) {
	ott, err := FindOneTimeToken(tx, token, EmailChangeTokenCurrent)
	if err != nil && !IsNotFoundError(err) {
		return nil, err
	}

	if ott == nil {
		ott, err = FindOneTimeToken(tx, "pkce_"+token, EmailChangeTokenCurrent)
		if err != nil {
			return nil, err
		}
	}
	if ott == nil {
		return nil, err
	}

	user, err := FindUserByID(tx, ott.UserID)
	if err != nil {
		return nil, err
	}

	if user.Aud != aud && strings.EqualFold(user.GetEmail(), email) {
		return nil, UserNotFoundError{}
	}

	return user, nil
}

// FindUserByEmailChangeNewAndAudience finds a user with the matching email change and audience.
func FindUserByEmailChangeNewAndAudience(tx *storage.Connection, email, token, aud string) (*User, error) {
	ott, err := FindOneTimeToken(tx, token, EmailChangeTokenNew)
	if err != nil && !IsNotFoundError(err) {
		return nil, err
	}

	if ott == nil {
		ott, err = FindOneTimeToken(tx, "pkce_"+token, EmailChangeTokenNew)
		if err != nil && !IsNotFoundError(err) {
			return nil, err
		}
	}
	if ott == nil {
		return nil, err
	}

	user, err := FindUserByID(tx, ott.UserID)
	if err != nil {
		return nil, err
	}

	if user.Aud != aud && strings.EqualFold(user.EmailChange, email) {
		return nil, UserNotFoundError{}
	}

	return user, nil
}

// FindUserForEmailChange finds a user requesting for an email change
func FindUserForEmailChange(tx *storage.Connection, email, token, aud string, secureEmailChangeEnabled bool) (*User, error) {
	if secureEmailChangeEnabled {
		if user, err := FindUserByEmailChangeCurrentAndAudience(tx, email, token, aud); err == nil {
			return user, err
		} else if !IsNotFoundError(err) {
			return nil, err
		}
	}
	return FindUserByEmailChangeNewAndAudience(tx, email, token, aud)
}

// FindUserForPhoneChange finds the user requesting a change to the given phone
// number, identifying them by their one-time token rather than by the phone
// number alone.
//
// The phone_change column carries no uniqueness constraint, so several users
// can hold the same pending value at once (abandoned or still-unverified change
// requests). Selecting on phone_change alone returns an arbitrary one of them,
// which can be a different user than the one the token was issued to. Email
// change already resolves its user through the one-time token for this reason
// (see FindUserForEmailChange); this does the same for phone change.
//
// Falls back to the phone_change lookup when no one-time token matches, so
// verification paths that do not go through the one_time_tokens table (test
// OTPs, rows predating it) keep working exactly as before.
func FindUserForPhoneChange(tx *storage.Connection, phone, tokenHash, aud string) (*User, error) {
	if tokenHash != "" {
		ott, err := FindOneTimeToken(tx, tokenHash, PhoneChangeToken)
		if err != nil && !IsNotFoundError(err) {
			return nil, err
		}
		if ott != nil {
			user, err := FindUserByID(tx, ott.UserID)
			if err != nil {
				return nil, err
			}
			if user.Aud == aud && user.PhoneChange == phone {
				return user, nil
			}
		}
	}

	return FindUserByPhoneChangeAndAudience(tx, phone, aud)
}
