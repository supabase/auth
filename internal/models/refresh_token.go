package models

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/gotrue/internal/crypto"
	"github.com/supabase/gotrue/internal/storage"
)

// RefreshToken is the database model for refresh tokens.
type RefreshToken struct {
	ID int64 `db:"id"`

	Token string `db:"token"`

	UserID uuid.UUID `db:"user_id"`

	Parent    storage.NullString `db:"parent"`
	SessionId *uuid.UUID         `db:"session_id"`

	Revoked   bool      `db:"revoked"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`

	DONTUSEINSTANCEID uuid.UUID `json:"-" db:"instance_id"`
}

func (RefreshToken) TableName() string {
	tableName := "refresh_tokens"
	return tableName
}

// GrantParams is used to pass session-specific parameters when issuing a new
// refresh token to authenticated users.
type GrantParams struct {
	FactorID *uuid.UUID

	SessionNotAfter *time.Time
}

// GrantAuthenticatedUser creates a refresh token for the provided user.
func GrantAuthenticatedUser(tx *storage.Connection, user *User, params GrantParams) (*RefreshToken, error) {
	return createRefreshToken(tx, user, nil, &params)
}

// GrantRefreshTokenSwap swaps a refresh token for a new one, revoking the provided token.
func GrantRefreshTokenSwap(r *http.Request, tx *storage.Connection, user *User, token *RefreshToken) (*RefreshToken, error) {
	var newToken *RefreshToken
	err := tx.Transaction(func(rtx *storage.Connection) error {
		var terr error
		if terr = NewAuditLogEntry(r, tx, user, TokenRevokedAction, "", nil); terr != nil {
			return errors.Wrap(terr, "error creating audit log entry")
		}

		token.Revoked = true
		if terr = tx.UpdateOnly(token, "revoked"); terr != nil {
			return terr
		}

		newToken, terr = createRefreshToken(rtx, user, token, &GrantParams{})
		return terr
	})
	return newToken, err
}

// RevokeTokenFamily revokes all refresh tokens that descended from the provided token.
func RevokeTokenFamily(tx *storage.Connection, token *RefreshToken) error {
	var err error
	tablename := (&pop.Model{Value: RefreshToken{}}).TableName()
	if token.SessionId != nil {
		err = tx.RawQuery(`update `+tablename+` set revoked = true where session_id = ? and revoked = false;`, token.SessionId).Exec()
	} else {
		err = tx.RawQuery(`
		with recursive token_family as (
			select id, user_id, token, revoked, parent from `+tablename+` where parent = ?
			union
			select r.id, r.user_id, r.token, r.revoked, r.parent from `+tablename+` r inner join token_family t on t.token = r.parent
		)
		update `+tablename+` r set revoked = true from token_family where token_family.id = r.id;`, token.Token).Exec()
	}
	if err != nil {
		return err
	}
	return nil
}

// GetValidChildToken returns the child token of the token provided if the child is not revoked.
func GetValidChildToken(tx *storage.Connection, token *RefreshToken) (*RefreshToken, error) {
	refreshToken := &RefreshToken{}
	err := tx.Q().Where("parent = ? and revoked = false", token.Token).First(refreshToken)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, RefreshTokenNotFoundError{}
		}
		return nil, err
	}
	return refreshToken, nil
}

func FindTokenBySessionID(tx *storage.Connection, sessionId *uuid.UUID) (*RefreshToken, error) {
	refreshToken := &RefreshToken{}
	err := tx.Q().Where("session_id = ?", sessionId).Order("created_at asc").First(refreshToken)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, RefreshTokenNotFoundError{}
		}
		return nil, err
	}
	return refreshToken, nil
}

func createRefreshToken(tx *storage.Connection, user *User, oldToken *RefreshToken, params *GrantParams) (*RefreshToken, error) {
	token := &RefreshToken{
		UserID: user.ID,
		Token:  crypto.SecureToken(),
		Parent: "",
	}
	if oldToken != nil {
		token.Parent = storage.NullString(oldToken.Token)
		token.SessionId = oldToken.SessionId

	}

	if token.SessionId == nil {
		session, err := NewSession()
		if err != nil {
			return nil, errors.Wrap(err, "error instantiating new session object")
		}

		session.UserID = user.ID

		if params.FactorID != nil {
			session.FactorID = params.FactorID
		}

		if params.SessionNotAfter != nil {
			session.NotAfter = params.SessionNotAfter
		}

		if err := tx.Create(session); err != nil {
			return nil, errors.Wrap(err, "error creating new session")
		}

		token.SessionId = &session.ID
	}

	if err := tx.Create(token); err != nil {
		return nil, errors.Wrap(err, "error creating refresh token")
	}

	if err := user.UpdateLastSignInAt(tx); err != nil {
		return nil, errors.Wrap(err, "error update user`s last_sign_in field")
	}
	return token, nil
}

// Deprecated. For backward compatibility, some access tokens may not have a sessionId. Use models.Logout instead.
// LogoutAllRefreshTokens deletes all sessions for a user.
func LogoutAllRefreshTokens(tx *storage.Connection, userId uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: RefreshToken{}}).TableName()+" WHERE user_id = ?", userId).Exec()
}
