package api

import (
	"time"

	"github.com/gofrs/uuid"
)


type Web3GrantParams struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Chain     string `json:"chain"`
}

type StoredNonce struct {
	ID        uuid.UUID `db:"id"`
	Nonce     string    `db:"nonce"`
	Address   string    `db:"address"`     // Optional: can be empty until signature verification
	CreatedAt time.Time `db:"created_at"`
	ExpiresAt time.Time `db:"expires_at"`
	Used      bool      `db:"used"`
}

func (StoredNonce) TableName() string {
	tableName := "nonces"
	return tableName
}