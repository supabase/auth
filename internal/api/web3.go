package api

import (
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/conf"
)

type Web3Provider struct {
	config       conf.Web3Configuration
	chains       map[string]conf.BlockchainConfig
	defaultChain string
}

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