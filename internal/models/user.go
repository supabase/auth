package models

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/storage"
)

// User respresents a registered user with email/password authentication
type User struct {
	ID uuid.UUID `json:"id" db:"id"`

	Aud       string             `json:"aud" db:"aud"`
	Role      string             `json:"role" db:"role"`
	Email     storage.NullString `json:"email" db:"email"`
	IsSSOUser bool               `json:"-" db:"is_sso_user"`

	EncryptedPassword string     `json:"-" db:"encrypted_password"`
	EmailConfirmedAt  *time.Time `json:"email_confirmed_at,omitempty" db:"email_confirmed_at"`
	InvitedAt         *time.Time `json:"invited_at,omitempty" db:"invited_at"`

	Phone            storage.NullString `json:"phone" db:"phone"`
	PhoneConfirmedAt *time.Time         `json:"phone_confirmed_at,omitempty" db:"phone_confirmed_at"`

	ConfirmationToken  string     `json:"-" db:"confirmation_token"`
	ConfirmationSentAt *time.Time `json:"confirmation_sent_at,omitempty" db:"confirmation_sent_at"`

	// For backward compatibility only. Use EmailConfirmedAt or PhoneConfirmedAt instead.
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty" db:"confirmed_at" rw:"r"`

	RecoveryToken  string     `json:"-" db:"recovery_token"`
	RecoverySentAt *time.Time `json:"recovery_sent_at,omitempty" db:"recovery_sent_at"`

	EmailChangeTokenCurrent  string     `json:"-" db:"email_change_token_current"`
	EmailChangeTokenNew      string     `json:"-" db:"email_change_token_new"`
	EmailChange              string     `json:"new_email,omitempty" db:"email_change"`
	EmailChangeSentAt        *time.Time `json:"email_change_sent_at,omitempty" db:"email_change_sent_at"`
	EmailChangeConfirmStatus int        `json:"-" db:"email_change_confirm_status"`

	PhoneChangeToken  string     `json:"-" db:"phone_change_token"`
	PhoneChange       string     `json:"new_phone,omitempty" db:"phone_change"`
	PhoneChangeSentAt *time.Time `json:"phone_change_sent_at,omitempty" db:"phone_change_sent_at"`

	ReauthenticationToken  string     `json:"-" db:"reauthentication_token"`
	ReauthenticationSentAt *time.Time `json:"reauthentication_sent_at,omitempty" db:"reauthentication_sent_at"`

	LastSignInAt *time.Time `json:"last_sign_in_at,omitempty" db:"last_sign_in_at"`

	AppMetaData  JSONMap `json:"app_metadata" db:"raw_app_meta_data"`
	UserMetaData JSONMap `json:"user_metadata" db:"raw_user_meta_data"`

	Factors    []Factor   `json:"factors,omitempty" has_many:"factors"`
	Identities []Identity `json:"identities" has_many:"identities"`

	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	BannedUntil *time.Time `json:"banned_until,omitempty" db:"banned_until"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	IsAnonymous bool       `json:"is_anonymous" db:"is_anonymous"`

	DONTUSEINSTANCEID uuid.UUID `json:"-" db:"instance_id"`
}

// NewUser initializes a new user from an email, password and user data.
func NewUser(phone, email, password, aud string, userData map[string]interface{}) (*User, error) {
	passwordHash := ""

	if password != "" {
		pw, err := crypto.GenerateFromPassword(context.Background(), password)
		if err != nil {
			return nil, err
		}

		passwordHash = pw
	}

	if userData == nil {
		userData = make(map[string]interface{})
	}

	id := uuid.Must(uuid.NewV4())
	user := &User{
		ID:                id,
		Aud:               aud,
		Email:             storage.NullString(strings.ToLower(email)),
		Phone:             storage.NullString(phone),
		UserMetaData:      userData,
		EncryptedPassword: passwordHash,
	}
	return user, nil
}

// TableName overrides the table name used by pop
func (User) TableName() string {
	tableName := "users"
	return tableName
}

// BeforeSave is invoked before the user is saved to the database
func (u *User) BeforeSave(tx *pop.Connection) error {
	if u.EmailConfirmedAt != nil && u.EmailConfirmedAt.IsZero() {
		u.EmailConfirmedAt = nil
	}
	if u.PhoneConfirmedAt != nil && u.PhoneConfirmedAt.IsZero() {
		u.PhoneConfirmedAt = nil
	}
	if u.InvitedAt != nil && u.InvitedAt.IsZero() {
		u.InvitedAt = nil
	}
	if u.ConfirmationSentAt != nil && u.ConfirmationSentAt.IsZero() {
		u.ConfirmationSentAt = nil
	}
	if u.RecoverySentAt != nil && u.RecoverySentAt.IsZero() {
		u.RecoverySentAt = nil
	}
	if u.EmailChangeSentAt != nil && u.EmailChangeSentAt.IsZero() {
		u.EmailChangeSentAt = nil
	}
	if u.PhoneChangeSentAt != nil && u.PhoneChangeSentAt.IsZero() {
		u.PhoneChangeSentAt = nil
	}
	if u.ReauthenticationSentAt != nil && u.ReauthenticationSentAt.IsZero() {
		u.ReauthenticationSentAt = nil
	}
	if u.LastSignInAt != nil && u.LastSignInAt.IsZero() {
		u.LastSignInAt = nil
	}
	if u.BannedUntil != nil && u.BannedUntil.IsZero() {
		u.BannedUntil = nil
	}
	return nil
}

// IsConfirmed checks if a user has already been
// registered and confirmed.
func (u *User) IsConfirmed() bool {
	return u.EmailConfirmedAt != nil
}

// HasBeenInvited checks if user has been invited
func (u *User) HasBeenInvited() bool {
	return u.InvitedAt != nil
}

// IsPhoneConfirmed checks if a user's phone has already been
// registered and confirmed.
func (u *User) IsPhoneConfirmed() bool {
	return u.PhoneConfirmedAt != nil
}

// SetRole sets the users Role to roleName
func (u *User) SetRole(tx *storage.Connection, roleName string) error {
	u.Role = strings.TrimSpace(roleName)
	return tx.UpdateOnly(u, "role")
}

// HasRole returns true when the users role is set to roleName
func (u *User) HasRole(roleName string) bool {
	return u.Role == roleName
}

// GetEmail returns the user's email as a string
func (u *User) GetEmail() string {
	return string(u.Email)
}

// GetPhone returns the user's phone number as a string
func (u *User) GetPhone() string {
	return string(u.Phone)
}

// UpdateUserMetaData sets all user data from a map of updates,
// ensuring that it doesn't override attributes that are not
// in the provided map.
func (u *User) UpdateUserMetaData(tx *storage.Connection, updates map[string]interface{}) error {
	if u.UserMetaData == nil {
		u.UserMetaData = updates
	} else {
		for key, value := range updates {
			if value != nil {
				u.UserMetaData[key] = value
			} else {
				delete(u.UserMetaData, key)
			}
		}
	}
	return tx.UpdateOnly(u, "raw_user_meta_data")
}

// UpdateAppMetaData updates all app data from a map of updates
func (u *User) UpdateAppMetaData(tx *storage.Connection, updates map[string]interface{}) error {
	if u.AppMetaData == nil {
		u.AppMetaData = updates
	} else {
		for key, value := range updates {
			if value != nil {
				u.AppMetaData[key] = value
			} else {
				delete(u.AppMetaData, key)
			}
		}
	}
	return tx.UpdateOnly(u, "raw_app_meta_data")
}

// UpdateAppMetaDataProviders updates the provider field in AppMetaData column
func (u *User) UpdateAppMetaDataProviders(tx *storage.Connection) error {
	providers, terr := FindProvidersByUser(tx, u)
	if terr != nil {
		return terr
	}
	payload := map[string]interface{}{
		"providers": providers,
	}
	if len(providers) > 0 {
		payload["provider"] = providers[0]
	}
	return u.UpdateAppMetaData(tx, payload)
}

// UpdateUserEmail updates the user's email to one of the identity's email
// if the current email used doesn't match any of the identities email
func (u *User) UpdateUserEmailFromIdentities(tx *storage.Connection) error {
	identities, terr := FindIdentitiesByUserID(tx, u.ID)
	if terr != nil {
		return terr
	}
	for _, i := range identities {
		if u.GetEmail() == i.GetEmail() {
			// there's an existing identity that uses the same email
			// so the user's email can be kept
			return nil
		}
	}

	var primaryIdentity *Identity
	for _, i := range identities {
		if _, terr := FindUserByEmailAndAudience(tx, i.GetEmail(), u.Aud); terr != nil {
			if IsNotFoundError(terr) {
				// the identity's email is not used by another user
				// so we can set it as the primary identity
				primaryIdentity = i
				break
			}
			return terr
		}
	}
	if primaryIdentity == nil {
		return UserEmailUniqueConflictError{}
	}
	// default to the first identity's email
	if terr := u.SetEmail(tx, primaryIdentity.GetEmail()); terr != nil {
		return terr
	}
	if primaryIdentity.GetEmail() == "" {
		u.EmailConfirmedAt = nil
		if terr := tx.UpdateOnly(u, "email_confirmed_at"); terr != nil {
			return terr
		}
	}
	return nil
}

// SetEmail sets the user's email
func (u *User) SetEmail(tx *storage.Connection, email string) error {
	u.Email = storage.NullString(email)
	return tx.UpdateOnly(u, "email")
}

// SetPhone sets the user's phone
func (u *User) SetPhone(tx *storage.Connection, phone string) error {
	u.Phone = storage.NullString(phone)
	return tx.UpdateOnly(u, "phone")
}

func (u *User) SetPassword(ctx context.Context, password string) error {
	if password == "" {
		u.EncryptedPassword = ""
		return nil
	}

	pw, err := crypto.GenerateFromPassword(ctx, password)
	if err != nil {
		return err
	}

	u.EncryptedPassword = pw

	return nil
}

// UpdatePassword updates the user's password. Use SetPassword outside of a transaction first!
func (u *User) UpdatePassword(tx *storage.Connection, sessionID *uuid.UUID) error {
	// These need to be reset because password change may mean the user no longer trusts the actions performed by the previous password.
	u.ConfirmationToken = ""
	u.ConfirmationSentAt = nil
	u.RecoveryToken = ""
	u.RecoverySentAt = nil
	u.EmailChangeTokenCurrent = ""
	u.EmailChangeTokenNew = ""
	u.EmailChangeSentAt = nil
	u.PhoneChangeToken = ""
	u.PhoneChangeSentAt = nil
	u.ReauthenticationToken = ""
	u.ReauthenticationSentAt = nil

	if err := tx.UpdateOnly(u, "encrypted_password", "confirmation_token", "confirmation_sent_at", "recovery_token", "recovery_sent_at", "email_change_token_current", "email_change_token_new", "email_change_sent_at", "phone_change_token", "phone_change_sent_at", "reauthentication_token", "reauthentication_sent_at"); err != nil {
		return err
	}

	if sessionID == nil {
		// log out user from all sessions to ensure reauthentication after password change
		return Logout(tx, u.ID)
	} else {
		// log out user from all other sessions to ensure reauthentication after password change
		return LogoutAllExceptMe(tx, *sessionID, u.ID)
	}
}

// Authenticate a user from a password
func (u *User) Authenticate(ctx context.Context, password string) bool {
	err := crypto.CompareHashAndPassword(ctx, u.EncryptedPassword, password)
	return err == nil
}

// ConfirmReauthentication resets the reauthentication token
func (u *User) ConfirmReauthentication(tx *storage.Connection) error {
	u.ReauthenticationToken = ""
	return tx.UpdateOnly(u, "reauthentication_token")
}

// Confirm resets the confimation token and sets the confirm timestamp
func (u *User) Confirm(tx *storage.Connection) error {
	u.ConfirmationToken = ""
	now := time.Now()
	u.EmailConfirmedAt = &now
	return tx.UpdateOnly(u, "confirmation_token", "email_confirmed_at")
}

// ConfirmPhone resets the confimation token and sets the confirm timestamp
func (u *User) ConfirmPhone(tx *storage.Connection) error {
	u.ConfirmationToken = ""
	now := time.Now()
	u.PhoneConfirmedAt = &now
	return tx.UpdateOnly(u, "confirmation_token", "phone_confirmed_at")
}

// UpdateLastSignInAt update field last_sign_in_at for user according to specified field
func (u *User) UpdateLastSignInAt(tx *storage.Connection) error {
	return tx.UpdateOnly(u, "last_sign_in_at")
}

// ConfirmEmailChange confirm the change of email for a user
func (u *User) ConfirmEmailChange(tx *storage.Connection, status int) error {
	email := u.EmailChange

	u.Email = storage.NullString(email)
	u.EmailChange = ""
	u.EmailChangeTokenCurrent = ""
	u.EmailChangeTokenNew = ""
	u.EmailChangeConfirmStatus = status

	if err := tx.UpdateOnly(
		u,
		"email",
		"email_change",
		"email_change_token_current",
		"email_change_token_new",
		"email_change_confirm_status",
	); err != nil {
		return err
	}

	if !u.IsConfirmed() {
		if err := u.Confirm(tx); err != nil {
			return err
		}
	}

	identity, err := FindIdentityByIdAndProvider(tx, u.ID.String(), "email")
	if err != nil {
		if IsNotFoundError(err) {
			// no email identity, not an error
			return nil
		}
		return err
	}

	if _, ok := identity.IdentityData["email"]; ok {
		identity.IdentityData["email"] = email
		if err := tx.UpdateOnly(identity, "identity_data"); err != nil {
			return err
		}
	}

	return nil
}

// ConfirmPhoneChange confirms the change of phone for a user
func (u *User) ConfirmPhoneChange(tx *storage.Connection) error {
	now := time.Now()
	phone := u.PhoneChange

	u.Phone = storage.NullString(phone)
	u.PhoneChange = ""
	u.PhoneChangeToken = ""
	u.PhoneConfirmedAt = &now

	if err := tx.UpdateOnly(
		u,
		"phone",
		"phone_change",
		"phone_change_token",
		"phone_confirmed_at",
	); err != nil {
		return err
	}

	identity, err := FindIdentityByIdAndProvider(tx, u.ID.String(), "phone")
	if err != nil {
		if IsNotFoundError(err) {
			// no phone identity, not an error
			return nil
		}

		return err
	}

	if _, ok := identity.IdentityData["phone"]; ok {
		identity.IdentityData["phone"] = phone
	}

	if err := tx.UpdateOnly(identity, "identity_data"); err != nil {
		return err
	}

	return nil
}

// Recover resets the recovery token
func (u *User) Recover(tx *storage.Connection) error {
	u.RecoveryToken = ""
	return tx.UpdateOnly(u, "recovery_token")
}

// CountOtherUsers counts how many other users exist besides the one provided
func CountOtherUsers(tx *storage.Connection, id uuid.UUID) (int, error) {
	userCount, err := tx.Q().Where("instance_id = ? and id != ?", uuid.Nil, id).Count(&User{})
	return userCount, errors.Wrap(err, "error finding registered users")
}

func findUser(tx *storage.Connection, query string, args ...interface{}) (*User, error) {
	obj := &User{}
	if err := tx.Eager().Q().Where(query, args...).First(obj); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, UserNotFoundError{}
		}
		return nil, errors.Wrap(err, "error finding user")
	}

	return obj, nil
}

// FindUserByConfirmationToken finds users with the matching confirmation token.
func FindUserByConfirmationOrRecoveryToken(tx *storage.Connection, token string) (*User, error) {
	user, err := findUser(tx, "(confirmation_token = ? or recovery_token = ?) and is_sso_user = false", token, token)
	if err != nil {
		return nil, ConfirmationOrRecoveryTokenNotFoundError{}
	}
	return user, nil
}

// FindUserByConfirmationToken finds users with the matching confirmation token.
func FindUserByConfirmationToken(tx *storage.Connection, token string) (*User, error) {
	user, err := findUser(tx, "confirmation_token = ? and is_sso_user = false", token)
	if err != nil {
		return nil, ConfirmationTokenNotFoundError{}
	}
	return user, nil
}

// FindUserByEmailAndAudience finds a user with the matching email and audience.
func FindUserByEmailAndAudience(tx *storage.Connection, email, aud string) (*User, error) {
	return findUser(tx, "instance_id = ? and LOWER(email) = ? and aud = ? and is_sso_user = false", uuid.Nil, strings.ToLower(email), aud)
}

// FindUserByPhoneAndAudience finds a user with the matching email and audience.
func FindUserByPhoneAndAudience(tx *storage.Connection, phone, aud string) (*User, error) {
	return findUser(tx, "instance_id = ? and phone = ? and aud = ? and is_sso_user = false", uuid.Nil, phone, aud)
}

// FindUserByID finds a user matching the provided ID.
func FindUserByID(tx *storage.Connection, id uuid.UUID) (*User, error) {
	return findUser(tx, "instance_id = ? and id = ?", uuid.Nil, id)
}

// FindUserByRecoveryToken finds a user with the matching recovery token.
func FindUserByRecoveryToken(tx *storage.Connection, token string) (*User, error) {
	return findUser(tx, "recovery_token = ? and is_sso_user = false", token)
}

// FindUserByEmailChangeToken finds a user with the matching email change token.
func FindUserByEmailChangeToken(tx *storage.Connection, token string) (*User, error) {
	return findUser(tx, "is_sso_user = false and (email_change_token_current = ? or email_change_token_new = ?)", token, token)
}

// FindUserWithRefreshToken finds a user from the provided refresh token. If
// forUpdate is set to true, then the SELECT statement used by the query has
// the form SELECT ... FOR UPDATE SKIP LOCKED. This means that a FOR UPDATE
// lock will only be acquired if there's no other lock. In case there is a
// lock, a IsNotFound(err) error will be returned.
func FindUserWithRefreshToken(tx *storage.Connection, token string, forUpdate bool) (*User, *RefreshToken, *Session, error) {
	refreshToken := &RefreshToken{}

	if forUpdate {
		// pop does not provide us with a way to execute FOR UPDATE
		// queries which lock the rows affected by the query from
		// being accessed by any other transaction that also uses FOR
		// UPDATE
		if err := tx.RawQuery(fmt.Sprintf("SELECT * FROM %q WHERE token = ? LIMIT 1 FOR UPDATE SKIP LOCKED;", refreshToken.TableName()), token).First(refreshToken); err != nil {
			if errors.Cause(err) == sql.ErrNoRows {
				return nil, nil, nil, RefreshTokenNotFoundError{}
			}

			return nil, nil, nil, errors.Wrap(err, "error finding refresh token for update")
		}
	}

	// once the rows are locked (if forUpdate was true), we can query again using pop
	if err := tx.Where("token = ?", token).First(refreshToken); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil, nil, RefreshTokenNotFoundError{}
		}
		return nil, nil, nil, errors.Wrap(err, "error finding refresh token")
	}

	user, err := FindUserByID(tx, refreshToken.UserID)
	if err != nil {
		return nil, nil, nil, err
	}

	var session *Session

	if refreshToken.SessionId != nil {
		sessionId := *refreshToken.SessionId

		if sessionId != uuid.Nil {
			session, err = FindSessionByID(tx, sessionId, forUpdate)
			if err != nil {
				if forUpdate {
					return nil, nil, nil, err
				}

				if !IsNotFoundError(err) {
					return nil, nil, nil, errors.Wrap(err, "error finding session from refresh token")
				}

				// otherwise, there's no session for this refresh token
			}
		}
	}

	return user, refreshToken, session, nil
}

// FindUsersInAudience finds users with the matching audience.
func FindUsersInAudience(tx *storage.Connection, aud string, pageParams *Pagination, sortParams *SortParams, filter string) ([]*User, error) {
	users := []*User{}
	q := tx.Q().Where("instance_id = ? and aud = ?", uuid.Nil, aud)

	if filter != "" {
		lf := "%" + filter + "%"
		// we must specify the collation in order to get case insensitive search for the JSON column
		q = q.Where("(email LIKE ? OR raw_user_meta_data->>'full_name' ILIKE ?)", lf, lf)
	}

	if sortParams != nil && len(sortParams.Fields) > 0 {
		for _, field := range sortParams.Fields {
			q = q.Order(field.Name + " " + string(field.Dir))
		}
	}

	var err error
	if pageParams != nil {
		err = q.Paginate(int(pageParams.Page), int(pageParams.PerPage)).All(&users)
		pageParams.Count = uint64(q.Paginator.TotalEntriesSize)
	} else {
		err = q.All(&users)
	}

	return users, err
}

// FindUserByEmailChangeCurrentAndAudience finds a user with the matching email change and audience.
func FindUserByEmailChangeCurrentAndAudience(tx *storage.Connection, email, token, aud string) (*User, error) {
	return findUser(
		tx,
		"instance_id = ? and LOWER(email) = ? and aud = ? and is_sso_user = false and (email_change_token_current = 'pkce_' || ? or email_change_token_current = ?)",
		uuid.Nil, strings.ToLower(email), aud, token, token,
	)
}

// FindUserByEmailChangeNewAndAudience finds a user with the matching email change and audience.
func FindUserByEmailChangeNewAndAudience(tx *storage.Connection, email, token, aud string) (*User, error) {
	return findUser(
		tx,
		"instance_id = ? and LOWER(email_change) = ? and aud = ? and is_sso_user = false and (email_change_token_new = 'pkce_' || ? or email_change_token_new = ?)",
		uuid.Nil, strings.ToLower(email), aud, token, token,
	)
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

// FindUserByPhoneChangeAndAudience finds a user with the matching phone change and audience.
func FindUserByPhoneChangeAndAudience(tx *storage.Connection, phone, aud string) (*User, error) {
	return findUser(tx, "instance_id = ? and phone_change = ? and aud = ? and is_sso_user = false", uuid.Nil, phone, aud)
}

// IsDuplicatedEmail returns whether a user exists with a matching email and audience.
// If a currentUser is provided, we will need to filter out any identities that belong to the current user.
func IsDuplicatedEmail(tx *storage.Connection, email, aud string, currentUser *User) (*User, error) {
	var identities []Identity

	if err := tx.Eager().Q().Where("email = ?", strings.ToLower(email)).All(&identities); err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			return nil, nil
		}

		return nil, errors.Wrap(err, "unable to find identity by email for duplicates")
	}

	userIDs := make(map[string]uuid.UUID)
	for _, identity := range identities {
		if _, ok := userIDs[identity.UserID.String()]; !ok {
			if !identity.IsForSSOProvider() {
				userIDs[identity.UserID.String()] = identity.UserID
			}
		}
	}

	var currentUserId uuid.UUID
	if currentUser != nil {
		currentUserId = currentUser.ID
	}

	for _, userID := range userIDs {
		if userID != currentUserId {
			user, err := FindUserByID(tx, userID)
			if err != nil {
				return nil, errors.Wrap(err, "unable to find user from email identity for duplicates")
			}
			if user.Aud == aud {
				return user, nil
			}
		}
	}

	// out of an abundance of caution, if nothing was found via the
	// identities table we also do a final check on the users table
	user, err := FindUserByEmailAndAudience(tx, email, aud)
	if err != nil && !IsNotFoundError(err) {
		return nil, errors.Wrap(err, "unable to find user email address for duplicates")
	}

	return user, nil
}

// IsDuplicatedPhone checks if the phone number already exists in the users table
func IsDuplicatedPhone(tx *storage.Connection, phone, aud string) (bool, error) {
	_, err := FindUserByPhoneAndAudience(tx, phone, aud)
	if err != nil {
		if IsNotFoundError(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Ban a user for a given duration.
func (u *User) Ban(tx *storage.Connection, duration time.Duration) error {
	if duration == time.Duration(0) {
		u.BannedUntil = nil
	} else {
		t := time.Now().Add(duration)
		u.BannedUntil = &t
	}
	return tx.UpdateOnly(u, "banned_until")
}

// IsBanned checks if a user is banned or not
func (u *User) IsBanned() bool {
	if u.BannedUntil == nil {
		return false
	}
	return time.Now().Before(*u.BannedUntil)
}

func (u *User) UpdateBannedUntil(tx *storage.Connection) error {
	return tx.UpdateOnly(u, "banned_until")
}

// RemoveUnconfirmedIdentities removes potentially malicious unconfirmed identities from a user (if any)
func (u *User) RemoveUnconfirmedIdentities(tx *storage.Connection, identity *Identity) error {
	if identity.Provider != "email" && identity.Provider != "phone" {
		// user is unconfirmed so the password should be reset
		u.EncryptedPassword = ""
		if terr := tx.UpdateOnly(u, "encrypted_password"); terr != nil {
			return terr
		}
	}

	// user is unconfirmed so existing user_metadata should be overwritten
	// to use the current identity metadata
	u.UserMetaData = identity.IdentityData
	if terr := u.UpdateUserMetaData(tx, u.UserMetaData); terr != nil {
		return terr
	}

	// finally, remove all identities except the current identity being authenticated
	for i := range u.Identities {
		if u.Identities[i].ID != identity.ID {
			if terr := tx.Destroy(&u.Identities[i]); terr != nil {
				return terr
			}
		}
	}

	// user is unconfirmed so none of the providers associated to it are verified yet
	// only the current provider should be kept
	if terr := u.UpdateAppMetaDataProviders(tx); terr != nil {
		return terr
	}
	return nil
}

// SoftDeleteUser performs a soft deletion on the user by obfuscating and clearing certain fields
func (u *User) SoftDeleteUser(tx *storage.Connection) error {
	u.Email = storage.NullString(obfuscateEmail(u, u.GetEmail()))
	u.Phone = storage.NullString(obfuscatePhone(u, u.GetPhone()))
	u.EmailChange = obfuscateEmail(u, u.EmailChange)
	u.PhoneChange = obfuscatePhone(u, u.PhoneChange)
	u.EncryptedPassword = ""
	u.ConfirmationToken = ""
	u.RecoveryToken = ""
	u.EmailChangeTokenCurrent = ""
	u.EmailChangeTokenNew = ""
	u.PhoneChangeToken = ""

	// set deleted_at time
	now := time.Now()
	u.DeletedAt = &now

	if err := tx.UpdateOnly(
		u,
		"email",
		"phone",
		"encrypted_password",
		"email_change",
		"phone_change",
		"confirmation_token",
		"recovery_token",
		"email_change_token_current",
		"email_change_token_new",
		"phone_change_token",
		"deleted_at",
	); err != nil {
		return err
	}

	// set raw_user_meta_data to {}
	userMetaDataUpdates := map[string]interface{}{}
	for k := range u.UserMetaData {
		userMetaDataUpdates[k] = nil
	}

	if err := u.UpdateUserMetaData(tx, userMetaDataUpdates); err != nil {
		return err
	}

	// set raw_app_meta_data to {}
	appMetaDataUpdates := map[string]interface{}{}
	for k := range u.AppMetaData {
		appMetaDataUpdates[k] = nil
	}

	if err := u.UpdateAppMetaData(tx, appMetaDataUpdates); err != nil {
		return err
	}

	return nil
}

// SoftDeleteUserIdentities performs a soft deletion on all identities associated to a user
func (u *User) SoftDeleteUserIdentities(tx *storage.Connection) error {
	identities, err := FindIdentitiesByUserID(tx, u.ID)
	if err != nil {
		return err
	}

	// set identity_data to {}
	for _, identity := range identities {
		identityDataUpdates := map[string]interface{}{}
		for k := range identity.IdentityData {
			identityDataUpdates[k] = nil
		}
		if err := identity.UpdateIdentityData(tx, identityDataUpdates); err != nil {
			return err
		}
		// updating the identity.ID has to happen last since the primary key is on (provider, id)
		// we use RawQuery here instead of UpdateOnly because UpdateOnly relies on the primary key of Identity
		if err := tx.RawQuery(
			"update "+
				(&pop.Model{Value: Identity{}}).TableName()+
				" set provider_id = ? where id = ?",
			obfuscateIdentityProviderId(identity),
			identity.ID,
		).Exec(); err != nil {
			return err
		}
	}
	return nil
}

func obfuscateValue(id uuid.UUID, value string) string {
	hash := sha256.Sum256([]byte(id.String() + value))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func obfuscateEmail(u *User, email string) string {
	return obfuscateValue(u.ID, email)
}

func obfuscatePhone(u *User, phone string) string {
	// Field converted from VARCHAR(15) to text
	return obfuscateValue(u.ID, phone)[:15]
}

func obfuscateIdentityProviderId(identity *Identity) string {
	return obfuscateValue(identity.UserID, identity.Provider+":"+identity.ProviderID)
}
