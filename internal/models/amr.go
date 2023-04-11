package models

import (
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/storage"
)

type AMRClaim struct {
	ID                   uuid.UUID `json:"id" db:"id"`
	SessionID            uuid.UUID `json:"session_id" db:"session_id"`
	CreatedAt            time.Time `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time `json:"updated_at" db:"updated_at"`
	AuthenticationMethod *string   `json:"authentication_method" db:"authentication_method"`
}

func (AMRClaim) TableName() string {
	tableName := "mfa_amr_claims"
	return tableName
}

func AddClaimToSession(tx *storage.Connection, session *Session, authenticationMethod AuthenticationMethod) error {
	id := uuid.Must(uuid.NewV4())

	currentTime := time.Now()
	return tx.RawQuery("INSERT INTO "+(&pop.Model{Value: AMRClaim{}}).TableName()+
		`(id, session_id, created_at, updated_at, authentication_method) values (?, ?, ?, ?, ?)
			ON CONFLICT ON CONSTRAINT mfa_amr_claims_session_id_authentication_method_pkey
			DO UPDATE SET updated_at = ?;`, id, session.ID, currentTime, currentTime, authenticationMethod.String(), currentTime).Exec()
}

func (a *AMRClaim) GetAuthenticationMethod() string {
	if a.AuthenticationMethod == nil {
		return ""
	}
	return *(a.AuthenticationMethod)
}
