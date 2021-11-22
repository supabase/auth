package models

import (
	"time"

	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/storage"
	"github.com/pkg/errors"
)

// RefreshToken is the database model for refresh tokens.
type RefreshToken struct {
	InstanceID uuid.UUID `json:"-" db:"instance_id"`
	ID         int64     `db:"id"`

	Token string `db:"token"`

	UserID uuid.UUID `db:"user_id"`

	Parent storage.NullString `db:"parent"`

	Revoked   bool      `db:"revoked"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (RefreshToken) TableName() string {
	tableName := "refresh_tokens"
	return tableName
}

// GrantAuthenticatedUser creates a refresh token for the provided user.
func GrantAuthenticatedUser(tx *storage.Connection, user *User) (*RefreshToken, error) {
	return createRefreshToken(tx, user, nil)
}

// GrantRefreshTokenSwap swaps a refresh token for a new one, revoking the provided token.
func GrantRefreshTokenSwap(tx *storage.Connection, user *User, token *RefreshToken) (*RefreshToken, error) {
	var newToken *RefreshToken
	err := tx.Transaction(func(rtx *storage.Connection) error {
		var terr error
		if terr = NewAuditLogEntry(tx, user.InstanceID, user, TokenRevokedAction, nil); terr != nil {
			return errors.Wrap(terr, "error creating audit log entry")
		}

		token.Revoked = true
		if terr = tx.UpdateOnly(token, "revoked"); terr != nil {
			return terr
		}
		newToken, terr = createRefreshToken(rtx, user, token)
		return terr
	})
	return newToken, err
}

// RevokeTokenFamily revokes all refresh tokens that descended from the provided token.
func RevokeTokenFamily(tx *storage.Connection, token *RefreshToken) error {
	err := tx.RawQuery(`
	with recursive token_family as (
		select id, user_id, token, revoked, parent from refresh_tokens where parent = ?
		union
		select r.id, r.user_id, r.token, r.revoked, r.parent from `+(&pop.Model{Value: RefreshToken{}}).TableName()+` r inner join token_family t on t.token = r.parent
	)
	update `+(&pop.Model{Value: RefreshToken{}}).TableName()+` r set revoked = true from token_family where token_family.id = r.id;`, token.Token).Exec()
	if err != nil {
		return err
	}
	return nil
}

// Logout deletes all refresh tokens for a user.
func Logout(tx *storage.Connection, instanceID uuid.UUID, id uuid.UUID) error {
	return tx.RawQuery("DELETE FROM "+(&pop.Model{Value: RefreshToken{}}).TableName()+" WHERE instance_id = ? AND user_id = ?", instanceID, id).Exec()
}

func createRefreshToken(tx *storage.Connection, user *User, oldToken *RefreshToken) (*RefreshToken, error) {
	token := &RefreshToken{
		InstanceID: user.InstanceID,
		UserID:     user.ID,
		Token:      crypto.SecureToken(),
		Parent:     "",
	}
	if oldToken != nil {
		token.Parent = storage.NullString(oldToken.Token)
	}

	if err := tx.Create(token); err != nil {
		return nil, errors.Wrap(err, "error creating refresh token")
	}

	if err := user.UpdateLastSignInAt(tx); err != nil {
		return nil, errors.Wrap(err, "error update user`s last_sign_in field")
	}
	return token, nil
}
