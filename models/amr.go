package models

import (
	"github.com/gobuffalo/pop/v5"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/storage"
	"time"
)

type AMRClaim struct {
	SessionID    uuid.UUID `json:"session_id" db:"session_id"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
	SignInMethod string    `json:"sign_in_method" db:"sign_in_method"`
}

func (AMRClaim) TableName() string {
	tableName := "mfa_amr_claims"
	return tableName
}

func AddClaimToSession(tx *storage.Connection, session *Session, signInMethod string) error {
	currentTime := time.Now()
	return tx.RawQuery("INSERT INTO "+(&pop.Model{Value: AMRClaim{}}).TableName()+
		"(session_id, created_at, updated_at, sign_in_method) values(?, ?, ?, ?) "+"ON CONFLICT ON CONSTRAINT mfa_amr_claims_session_id_sign_in_method_pkey "+"DO UPDATE SET updated_at = ?;", session.ID, currentTime, currentTime, signInMethod, currentTime).Exec()
}
