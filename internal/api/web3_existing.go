package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// Signed intent prevents downgrading an existing-only proof to ordinary signup.
const web3ExistingRequestID = "WEB3_EXISTING_USER_ONLY"
const web3ExistingChallengeTTL = 5 * time.Minute

type web3ExistingChallenge struct {
	ID         uuid.UUID  `db:"id"`
	NonceHash  string     `db:"nonce_hash"`
	ProviderID string     `db:"provider_id"`
	IdentityID uuid.UUID  `db:"identity_id"`
	UserID     uuid.UUID  `db:"user_id"`
	Chain      string     `db:"chain"`
	ChainID    string     `db:"chain_id"`
	Domain     string     `db:"domain"`
	URI        string     `db:"uri"`
	CreatedAt  time.Time  `db:"created_at"`
	ExpiresAt  time.Time  `db:"expires_at"`
	ConsumedAt *time.Time `db:"consumed_at"`
}

func (web3ExistingChallenge) TableName() string { return "web3_login_challenges" }

func web3ExistingDenied() error {
	return apierrors.NewOAuthError("invalid_grant", "Existing Web3 identity or challenge is unavailable")
}

func web3ProviderID(chain, address string) (string, bool) {
	switch chain {
	case "ethereum":
		if !common.IsHexAddress(address) {
			return "", false
		}
		return "web3:ethereum:" + strings.ToLower(address), true
	case "solana":
		if len(base58.Decode(address)) != 32 {
			return "", false
		}
		return "web3:solana:" + address, true
	default:
		return "", false
	}
}

func web3SameProviderID(chain, a, b string) bool {
	if chain == "ethereum" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Locks both identity and user before returning a principal. Per-user locking
// also avoids upgrading simultaneous SHARE locks during session issuance.
func lockExistingWeb3(tx *storage.Connection, chain, providerID string) (*models.Identity, *models.User, error) {
	identities := []models.Identity{}
	identityTable := (&pop.Model{Value: models.Identity{}}).TableName()
	userTable := (&pop.Model{Value: models.User{}}).TableName()
	match := "i.provider_id = ?"
	if chain == "ethereum" {
		match = "lower(i.provider_id) = lower(?)"
	}
	query := "select i.* from " + identityTable + " i join " + userTable + " u on u.id=i.user_id where i.provider='web3' and " + match + " order by i.id for update of i,u"
	if err := tx.RawQuery(query, providerID).All(&identities); err != nil {
		return nil, nil, err
	}
	// Refuse case-folding ambiguities instead of choosing an arbitrary account.
	if len(identities) != 1 {
		return nil, nil, web3ExistingDenied()
	}
	i := &identities[0]
	u, err := models.FindUserByID(tx, i.UserID)
	if err != nil {
		return nil, nil, web3ExistingDenied()
	}
	sub, _ := i.IdentityData["sub"].(string)
	claims, _ := i.IdentityData["custom_claims"].(map[string]interface{})
	address, _ := claims["address"].(string)
	storedChain, _ := claims["chain"].(string)
	storedID, valid := web3ProviderID(storedChain, address)
	if u.DeletedAt != nil || u.IsBanned() || u.IsAnonymous || i.LastSignInAt == nil ||
		!valid || storedChain != chain || !web3SameProviderID(chain, sub, providerID) ||
		!web3SameProviderID(chain, storedID, providerID) {
		return nil, nil, web3ExistingDenied()
	}
	return i, u, nil
}

type Web3ChallengeParams struct {
	Chain          string `json:"chain"`
	Address        string `json:"address"`
	ChainID        string `json:"chain_id"`
	Domain         string `json:"domain"`
	URI            string `json:"uri"`
	ExpectedUserID string `json:"expected_user_id"`
}

// Web3ExistingChallenge issues only a nonce, never a user or session. Request
// fields are constraints, not evidence of authority; the signed proof is still
// checked by the existing Web3 grant validators before challenge consumption.
func (a *API) Web3ExistingChallenge(w http.ResponseWriter, r *http.Request) error {
	var input Web3ChallengeParams
	if err := retrieveRequestParams(r, &input); err != nil {
		return err
	}
	providerID, valid := web3ProviderID(input.Chain, input.Address)
	if !valid || (input.Chain == "ethereum" && !a.config.External.Web3Ethereum.Enabled) ||
		(input.Chain == "solana" && !a.config.External.Web3Solana.Enabled) {
		return web3ExistingDenied()
	}
	uri, err := url.Parse(input.URI)
	if err != nil || uri.Host == "" || uri.Host != input.Domain || uri.User != nil ||
		(uri.Scheme != "https" && !(uri.Scheme == "http" && uri.Hostname() == "localhost")) ||
		!utilities.IsRedirectURLValid(a.config, uri.String()) || input.ChainID == "" || len(input.ChainID) > 64 {
		return web3ExistingDenied()
	}
	if input.Chain == "ethereum" {
		chainID, err := strconv.ParseUint(input.ChainID, 10, 64)
		if err != nil || chainID == 0 || strconv.FormatUint(chainID, 10) != input.ChainID {
			return web3ExistingDenied()
		}
	}
	if input.ExpectedUserID != "" {
		if _, err := uuid.FromString(input.ExpectedUserID); err != nil {
			return web3ExistingDenied()
		}
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return err
	}
	nonce := hex.EncodeToString(nonceBytes)
	hash := sha256.Sum256([]byte(nonce))
	now := a.Now().UTC().Truncate(time.Second)
	challenge := &web3ExistingChallenge{ID: uuid.Must(uuid.NewV4()), NonceHash: hex.EncodeToString(hash[:]),
		ProviderID: providerID, Chain: input.Chain, ChainID: input.ChainID,
		Domain: input.Domain, URI: input.URI, CreatedAt: now, ExpiresAt: now.Add(web3ExistingChallengeTTL)}
	err = a.db.WithContext(r.Context()).Transaction(func(tx *storage.Connection) error {
		if err := tx.RawQuery("set local lock_timeout='3s'").Exec(); err != nil {
			return err
		}
		i, u, err := lockExistingWeb3(tx, input.Chain, providerID)
		if err != nil {
			return err
		}
		if input.ExpectedUserID != "" && input.ExpectedUserID != u.ID.String() {
			return web3ExistingDenied()
		}
		challenge.IdentityID, challenge.UserID = i.ID, u.ID
		return tx.Create(challenge)
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, map[string]interface{}{
		"nonce": nonce, "request_id": web3ExistingRequestID,
		"issued_at": now, "expires_at": challenge.ExpiresAt,
	})
}

// consumeExistingWeb3 runs only after the official cryptographic validators.
// It has no account/identity creation call, including on missing or changed rows.
func consumeExistingWeb3(tx *storage.Connection, params *Web3GrantParams, providerID, nonce, domain, uri, chainID string, issuedAt, expiresAt time.Time) (*models.User, error) {
	if err := tx.RawQuery("set local lock_timeout='3s'").Exec(); err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(nonce))
	challenge := &web3ExistingChallenge{}
	table := (&pop.Model{Value: web3ExistingChallenge{}}).TableName()
	if err := tx.RawQuery("select * from "+table+" where nonce_hash=? for update", hex.EncodeToString(hash[:])).First(challenge); err != nil {
		return nil, web3ExistingDenied()
	}
	if challenge.ConsumedAt != nil || params.Chain != challenge.Chain || domain != challenge.Domain ||
		uri != challenge.URI || chainID != challenge.ChainID || !web3SameProviderID(params.Chain, providerID, challenge.ProviderID) ||
		issuedAt.Before(challenge.CreatedAt.Add(-30*time.Second)) || expiresAt.IsZero() || expiresAt.Before(issuedAt) || expiresAt.After(challenge.ExpiresAt) ||
		(params.ExpectedUserID != "" && params.ExpectedUserID != challenge.UserID.String()) {
		return nil, web3ExistingDenied()
	}
	i, u, err := lockExistingWeb3(tx, params.Chain, providerID)
	if err != nil {
		return nil, err
	}
	if i.ID != challenge.IdentityID || u.ID != challenge.UserID {
		return nil, web3ExistingDenied()
	}
	// Check database wall time after row-lock waits. Consumption and session
	// issuance commit together; an issuer/hook error rolls consumption back.
	var consumed string
	if err := tx.RawQuery("update "+table+" set consumed_at=clock_timestamp() where nonce_hash=? and consumed_at is null and expires_at>clock_timestamp() and ?>clock_timestamp() and ?<=clock_timestamp()+interval '30 seconds' returning nonce_hash", challenge.NonceHash, expiresAt, issuedAt).First(&consumed); err != nil {
		return nil, web3ExistingDenied()
	}
	return u, nil
}
