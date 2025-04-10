package models

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

type AuditAction string
type auditLogType string

const (
	LoginAction                     AuditAction = "login"
	LogoutAction                    AuditAction = "logout"
	InviteAcceptedAction            AuditAction = "invite_accepted"
	UserSignedUpAction              AuditAction = "user_signedup"
	UserInvitedAction               AuditAction = "user_invited"
	UserDeletedAction               AuditAction = "user_deleted"
	UserModifiedAction              AuditAction = "user_modified"
	UserRecoveryRequestedAction     AuditAction = "user_recovery_requested"
	UserReauthenticateAction        AuditAction = "user_reauthenticate_requested"
	UserConfirmationRequestedAction AuditAction = "user_confirmation_requested"
	UserRepeatedSignUpAction        AuditAction = "user_repeated_signup"
	UserUpdatePasswordAction        AuditAction = "user_updated_password"
	TokenRevokedAction              AuditAction = "token_revoked"
	TokenRefreshedAction            AuditAction = "token_refreshed"
	GenerateRecoveryCodesAction     AuditAction = "generate_recovery_codes"
	EnrollFactorAction              AuditAction = "factor_in_progress"
	UnenrollFactorAction            AuditAction = "factor_unenrolled"
	CreateChallengeAction           AuditAction = "challenge_created"
	VerifyFactorAction              AuditAction = "verification_attempted"
	DeleteFactorAction              AuditAction = "factor_deleted"
	DeleteRecoveryCodesAction       AuditAction = "recovery_codes_deleted"
	UpdateFactorAction              AuditAction = "factor_updated"
	MFACodeLoginAction              AuditAction = "mfa_code_login"
	IdentityUnlinkAction            AuditAction = "identity_unlinked"

	account       auditLogType = "account"
	team          auditLogType = "team"
	token         auditLogType = "token"
	user          auditLogType = "user"
	factor        auditLogType = "factor"
	recoveryCodes auditLogType = "recovery_codes"
)

var ActionLogTypeMap = map[AuditAction]auditLogType{
	LoginAction:                     account,
	LogoutAction:                    account,
	InviteAcceptedAction:            account,
	UserSignedUpAction:              team,
	UserInvitedAction:               team,
	UserDeletedAction:               team,
	TokenRevokedAction:              token,
	TokenRefreshedAction:            token,
	UserModifiedAction:              user,
	UserRecoveryRequestedAction:     user,
	UserConfirmationRequestedAction: user,
	UserRepeatedSignUpAction:        user,
	UserUpdatePasswordAction:        user,
	GenerateRecoveryCodesAction:     user,
	EnrollFactorAction:              factor,
	UnenrollFactorAction:            factor,
	CreateChallengeAction:           factor,
	VerifyFactorAction:              factor,
	DeleteFactorAction:              factor,
	UpdateFactorAction:              factor,
	MFACodeLoginAction:              factor,
	DeleteRecoveryCodesAction:       recoveryCodes,
}

// AuditLogEntry is the database model for audit log entries.
type AuditLogEntry struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Payload   JSONMap   `json:"payload" db:"payload"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	IPAddress string    `json:"ip_address" db:"ip_address"`

	DONTUSEINSTANCEID uuid.UUID `json:"-" db:"instance_id"`
}

func (AuditLogEntry) TableName() string {
	tableName := "audit_log_entries"
	return tableName
}

func NewAuditLogEntry(r *http.Request, tx *storage.Connection, actor *User, action AuditAction, ipAddress string, traits map[string]interface{}) error {
	id := uuid.Must(uuid.NewV4())

	username := actor.GetEmail()

	if actor.GetPhone() != "" {
		username = actor.GetPhone()
	}

	payload := map[string]interface{}{
		"actor_id":       actor.ID,
		"actor_via_sso":  actor.IsSSOUser,
		"actor_username": username,
		"action":         action,
		"log_type":       ActionLogTypeMap[action],
	}
	l := AuditLogEntry{
		ID:        id,
		Payload:   JSONMap(payload),
		IPAddress: ipAddress,
	}

	observability.LogEntrySetFields(r, logrus.Fields{
		"auth_event": logrus.Fields(payload),
	})

	if name, ok := actor.UserMetaData["full_name"]; ok {
		l.Payload["actor_name"] = name
	}

	if traits != nil {
		l.Payload["traits"] = traits
	}

	if err := tx.Create(&l); err != nil {
		return errors.Wrap(err, "Database error creating audit log entry")
	}

	return nil
}

func FindAuditLogEntries(tx *storage.Connection, filterColumns []string, filterValue string, pageParams *Pagination) ([]*AuditLogEntry, error) {
	q := tx.Q().Order("created_at desc").Where("instance_id = ?", uuid.Nil)

	if len(filterColumns) > 0 && filterValue != "" {
		lf := "%" + filterValue + "%"

		builder := bytes.NewBufferString("(")
		values := make([]interface{}, len(filterColumns))

		for idx, col := range filterColumns {
			builder.WriteString(fmt.Sprintf("payload->>'%s' ILIKE ?", col))
			values[idx] = lf

			if idx+1 < len(filterColumns) {
				builder.WriteString(" OR ")
			}
		}
		builder.WriteString(")")

		q = q.Where(builder.String(), values...)
	}

	logs := []*AuditLogEntry{}
	var err error
	if pageParams != nil {
		err = q.Paginate(int(pageParams.Page), int(pageParams.PerPage)).All(&logs) // #nosec G115
		pageParams.Count = uint64(q.Paginator.TotalEntriesSize)                    // #nosec G115
	} else {
		err = q.All(&logs)
	}

	return logs, err
}
