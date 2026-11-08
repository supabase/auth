package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/storage"
)

type r8Wallet struct {
	chain, chainID, address string
	eth                     *ecdsa.PrivateKey
	solana                  ed25519.PrivateKey
}

func r8NewWallet(t *testing.T, chain string) r8Wallet {
	if chain == "ethereum" {
		key, err := crypto.GenerateKey()
		require.NoError(t, err)
		return r8Wallet{chain: chain, chainID: "1", address: crypto.PubkeyToAddress(key.PublicKey).Hex(), eth: key}
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return r8Wallet{chain: chain, chainID: "solana:mainnet", address: base58.Encode(pub), solana: key}
}

func r8HTTP(api *API, path string, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "http://localhost"+path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, r)
	return w
}

func r8Proof(t *testing.T, wallet r8Wallet, nonce string, issued, expires time.Time, strict bool) map[string]interface{} {
	network := "Ethereum"
	if wallet.chain == "solana" {
		network = "Solana"
	}
	message := fmt.Sprintf("example.netlify.com wants you to sign in with your %s account:\n%s\n\nSign in to the isolated R8 test.\n\nURI: https://example.netlify.com\nVersion: 1\nChain ID: %s\nNonce: %s\nIssued At: %s\nExpiration Time: %s", network, wallet.address, wallet.chainID, nonce, issued.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano))
	if strict {
		message += "\nRequest ID: " + web3ExistingRequestID
	}
	signature := r8Signature(t, wallet, message)
	return map[string]interface{}{"chain": wallet.chain, "message": message, "signature": signature, "existing_user_only": strict}
}

func r8Signature(t *testing.T, wallet r8Wallet, message string) string {
	var signature string
	if wallet.chain == "ethereum" {
		sig, err := crypto.Sign(accounts.TextHash([]byte(message)), wallet.eth)
		require.NoError(t, err)
		sig[64] += 27
		signature = hexutil.Encode(sig)
	} else {
		signature = base64.StdEncoding.EncodeToString(ed25519.Sign(wallet.solana, []byte(message)))
	}
	return signature
}

type r8Counts struct {
	Users, Identities, Sessions int
	IdentityBindings, UserState string
	Audits, RefreshTokens       int
}

func r8Count(t *testing.T, db *storage.Connection) r8Counts {
	var result struct {
		Users            int    `db:"users"`
		Identities       int    `db:"identities"`
		Sessions         int    `db:"sessions"`
		IdentityBindings string `db:"identity_bindings"`
		UserState        string `db:"user_state"`
		Audits           int    `db:"audits"`
		RefreshTokens    int    `db:"refresh_tokens"`
	}
	require.NoError(t, db.RawQuery("select (select count(*) from auth.users) as users, (select count(*) from auth.identities) as identities, (select count(*) from auth.sessions) as sessions, (select md5(coalesce(string_agg(id::text || user_id::text || provider_id || identity_data::text,'|' order by id),'')) from auth.identities) as identity_bindings, (select md5(coalesce(string_agg(to_jsonb(u)::text,'|' order by id),'')) from auth.users u) as user_state, (select count(*) from auth.audit_log_entries) as audits, (select count(*) from auth.refresh_tokens) as refresh_tokens").First(&result))
	return r8Counts{result.Users, result.Identities, result.Sessions, result.IdentityBindings, result.UserState, result.Audits, result.RefreshTokens}
}

func r8NoCreate(t *testing.T, before, after r8Counts) {
	t.Logf("AUTH_COUNTS before_users=%d after_users=%d before_identities=%d after_identities=%d before_sessions=%d after_sessions=%d", before.Users, after.Users, before.Identities, after.Identities, before.Sessions, after.Sessions)
	require.Equal(t, before.Users, after.Users)
	require.Equal(t, before.Identities, after.Identities)
	require.Equal(t, before.IdentityBindings, after.IdentityBindings)
	t.Log("IDENTITY_AND_WALLET_BINDINGS_UNCHANGED=true")
}

func r8Seed(t *testing.T, api *API, wallet r8Wallet) string {
	now := time.Now().UTC()
	w := r8HTTP(api, "/token?grant_type=web3", r8Proof(t, wallet, "ordinarysignupnonce", now, now.Add(4*time.Minute), false))
	require.Equal(t, 200, w.Code, "ordinary fixture signup must succeed")
	var response struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.NotEmpty(t, response.User.ID)
	return response.User.ID
}

func r8Challenge(t *testing.T, api *API, wallet r8Wallet, userID string) map[string]interface{} {
	w := r8HTTP(api, "/web3/challenge", map[string]interface{}{"chain": wallet.chain, "address": wallet.address, "chain_id": wallet.chainID, "domain": "example.netlify.com", "uri": "https://example.netlify.com", "expected_user_id": userID})
	require.Equal(t, 200, w.Code, "existing-only challenge must succeed")
	var response struct {
		Nonce     string    `json:"nonce"`
		IssuedAt  time.Time `json:"issued_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	return r8Proof(t, wallet, response.Nonce, response.IssuedAt, response.ExpiresAt, true)
}

// A real PostgreSQL lock wait is the synchronization barrier, not a sleep
// masquerading as concurrent execution and not a mocked resolver.
func r8WaitLock(t *testing.T, db *storage.Connection) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		require.NoError(t, db.RawQuery("select count(*) from pg_stat_activity where datname=current_database() and wait_event_type='Lock'").First(&waiting))
		if waiting > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("real PostgreSQL lock waiter was not observed")
}

func TestR8Web3ExistingOnly(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)
	defer api.db.Close()
	config.External.Web3Ethereum.Enabled = true
	config.External.Web3Solana.Enabled = true

	reset := func(t *testing.T) {
		require.NoError(t, api.db.RawQuery("truncate auth.users cascade").Exec())
		require.NoError(t, api.db.RawQuery("truncate auth.web3_login_challenges").Exec())
	}
	for _, chain := range []string{"ethereum", "solana"} {
		t.Run("positive_"+chain, func(t *testing.T) {
			reset(t)
			wallet := r8NewWallet(t, chain)
			id := r8Seed(t, api, wallet)
			require.NoError(t, api.db.RawQuery("update auth.users set last_sign_in_at=clock_timestamp()-interval '1 hour' where id=?", id).Exec())
			proof := r8Challenge(t, api, wallet, id)
			proof["expected_user_id"] = id
			before := r8Count(t, api.db)
			w := r8HTTP(api, "/token?grant_type=web3", proof)
			require.Equal(t, 200, w.Code)
			var response struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				User         struct {
					ID           string    `json:"id"`
					LastSignInAt time.Time `json:"last_sign_in_at"`
				} `json:"user"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			require.Equal(t, id, response.User.ID)
			require.NotEmpty(t, response.AccessToken)
			require.True(t, time.Since(response.User.LastSignInAt) < time.Minute)
			r8NoCreate(t, before, r8Count(t, api.db))
			// Verify the real issued access token through GoTrue, not a decoded mock.
			r := httptest.NewRequest(http.MethodGet, "http://localhost/user", nil)
			r.Header.Set("Authorization", "Bearer "+response.AccessToken)
			verified := httptest.NewRecorder()
			api.handler.ServeHTTP(verified, r)
			require.Equal(t, 200, verified.Code)
			var principal struct {
				ID string `json:"id"`
			}
			require.NoError(t, json.Unmarshal(verified.Body.Bytes(), &principal))
			require.Equal(t, id, principal.ID)
			refreshed := r8HTTP(api, "/token?grant_type=refresh_token", map[string]interface{}{"refresh_token": response.RefreshToken})
			require.Equal(t, 200, refreshed.Code)
			var refreshResponse struct {
				User struct {
					ID           string    `json:"id"`
					LastSignInAt time.Time `json:"last_sign_in_at"`
				} `json:"user"`
			}
			require.NoError(t, json.Unmarshal(refreshed.Body.Bytes(), &refreshResponse))
			require.Equal(t, id, refreshResponse.User.ID)
			require.Equal(t, response.User.LastSignInAt.UnixMicro(), refreshResponse.User.LastSignInAt.UnixMicro())
			r8NoCreate(t, before, r8Count(t, api.db))
		})
	}

	t.Run("absent_identity_never_signs_up", func(t *testing.T) {
		reset(t)
		wallet := r8NewWallet(t, "ethereum")
		before := r8Count(t, api.db)
		now := time.Now().UTC()
		w := r8HTTP(api, "/token?grant_type=web3", r8Proof(t, wallet, "notaservernonce123", now, now.Add(time.Minute), true))
		require.NotEqual(t, 200, w.Code)
		r8NoCreate(t, before, r8Count(t, api.db))
	})

	negativeCases := []string{"deleted_user", "deleted_identity", "replacement_identity", "different_owner", "expected_uuid_mismatch", "unverified_identity", "invalid_signature", "expired_nonce", "wrong_domain", "wrong_chain", "downgrade", "missing_signed_intent", "banned_user", "expired_proof", "future_proof", "missing_expiration", "other_wallet_proof", "soft_deleted_user", "identity_subject_mismatch"}
	for _, name := range negativeCases {
		t.Run(name, func(t *testing.T) {
			reset(t)
			wallet := r8NewWallet(t, "ethereum")
			id := r8Seed(t, api, wallet)
			proof := r8Challenge(t, api, wallet, id)
			switch name {
			case "soft_deleted_user":
				require.NoError(t, api.db.RawQuery("update auth.users set deleted_at=clock_timestamp() where id=?", id).Exec())
			case "identity_subject_mismatch":
				require.NoError(t, api.db.RawQuery(`update auth.identities set identity_data=jsonb_set(identity_data,'{sub}','"wrong-subject"') where user_id=?`, id).Exec())
			case "deleted_user":
				require.NoError(t, api.db.RawQuery("delete from auth.users where id=?", id).Exec())
			case "deleted_identity":
				require.NoError(t, api.db.RawQuery("delete from auth.identities where user_id=?", id).Exec())
			case "replacement_identity":
				require.NoError(t, api.db.RawQuery("update auth.identities set id=gen_random_uuid() where user_id=?", id).Exec())
			case "different_owner":
				other := r8Seed(t, api, r8NewWallet(t, "ethereum"))
				require.NoError(t, api.db.RawQuery("update auth.identities set user_id=? where user_id=?", other, id).Exec())
			case "expected_uuid_mismatch":
				proof["expected_user_id"] = "00000000-0000-0000-0000-000000000001"
			case "unverified_identity":
				require.NoError(t, api.db.RawQuery("update auth.identities set last_sign_in_at=null where user_id=?", id).Exec())
			case "invalid_signature":
				proof["signature"] = "0x" + strings.Repeat("00", 65)
			case "expired_nonce":
				require.NoError(t, api.db.RawQuery("update auth.web3_login_challenges set created_at=clock_timestamp()-interval '10 minutes', expires_at=clock_timestamp()-interval '1 minute'").Exec())
			case "wrong_domain":
				proof["message"] = strings.ReplaceAll(proof["message"].(string), "example.netlify.com", "attacker.example")
			case "wrong_chain":
				proof["message"] = strings.Replace(proof["message"].(string), "Chain ID: 1", "Chain ID: 5", 1)
			case "downgrade":
				proof["existing_user_only"] = false
			case "missing_signed_intent":
				proof["message"] = strings.Replace(proof["message"].(string), "\nRequest ID: "+web3ExistingRequestID, "", 1)
			case "expired_proof", "future_proof", "missing_expiration":
				lines := strings.Split(proof["message"].(string), "\n")
				changed := []string{}
				for _, line := range lines {
					if strings.HasPrefix(line, "Expiration Time:") && name == "missing_expiration" {
						continue
					}
					if strings.HasPrefix(line, "Expiration Time:") && name == "expired_proof" {
						line = "Expiration Time: " + time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
					}
					if strings.HasPrefix(line, "Issued At:") && name == "expired_proof" {
						line = "Issued At: " + time.Now().Add(-2*time.Minute).UTC().Format(time.RFC3339)
					}
					if strings.HasPrefix(line, "Issued At:") && name == "future_proof" {
						line = "Issued At: " + time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
					}
					changed = append(changed, line)
				}
				proof["message"] = strings.Join(changed, "\n")
				proof["signature"] = r8Signature(t, wallet, proof["message"].(string))
			case "other_wallet_proof":
				otherWallet := r8NewWallet(t, "ethereum")
				r8Seed(t, api, otherWallet)
				proof["message"] = strings.Replace(proof["message"].(string), wallet.address, otherWallet.address, 1)
				proof["signature"] = r8Signature(t, otherWallet, proof["message"].(string))
			case "banned_user":
				require.NoError(t, api.db.RawQuery("update auth.users set banned_until=clock_timestamp()+interval '1 day' where id=?", id).Exec())
			}
			if name == "wrong_domain" || name == "wrong_chain" || name == "missing_signed_intent" {
				proof["signature"] = r8Signature(t, wallet, proof["message"].(string))
			}
			before := r8Count(t, api.db)
			w := r8HTTP(api, "/token?grant_type=web3", proof)
			require.Equal(t, http.StatusBadRequest, w.Code)
			after := r8Count(t, api.db)
			r8NoCreate(t, before, after)
			require.Equal(t, before.Sessions, after.Sessions)
		})
	}

	t.Run("ten_concurrent_same_proofs_one_session_no_user", func(t *testing.T) {
		reset(t)
		wallet := r8NewWallet(t, "ethereum")
		id := r8Seed(t, api, wallet)
		proof := r8Challenge(t, api, wallet, id)
		before := r8Count(t, api.db)
		results := make(chan int, 10)
		var workers sync.WaitGroup
		for range 10 {
			workers.Add(1)
			go func() { defer workers.Done(); results <- r8HTTP(api, "/token?grant_type=web3", proof).Code }()
		}
		workers.Wait()
		close(results)
		accepted := 0
		for code := range results {
			if code == 200 {
				accepted++
			}
		}
		require.Equal(t, 1, accepted)
		after := r8Count(t, api.db)
		r8NoCreate(t, before, after)
		require.Equal(t, before.Sessions+1, after.Sessions)
		// The exact successful proof cannot produce another session later either.
		require.NotEqual(t, 200, r8HTTP(api, "/token?grant_type=web3", proof).Code)
		require.Equal(t, after, r8Count(t, api.db))
	})

	for _, mutation := range []string{"delete", "transfer"} {
		t.Run("concurrent_identity_"+mutation, func(t *testing.T) {
			reset(t)
			wallet := r8NewWallet(t, "ethereum")
			id := r8Seed(t, api, wallet)
			other := r8Seed(t, api, r8NewWallet(t, "ethereum"))
			proof := r8Challenge(t, api, wallet, id)
			result := make(chan int, 1)
			before := r8Count(t, api.db)
			require.NoError(t, api.db.Transaction(func(tx *storage.Connection) error {
				if err := tx.RawQuery("lock table auth.identities in access exclusive mode").Exec(); err != nil {
					return err
				}
				go func() { result <- r8HTTP(api, "/token?grant_type=web3", proof).Code }()
				r8WaitLock(t, api.db)
				if mutation == "delete" {
					return tx.RawQuery("delete from auth.identities where user_id=?", id).Exec()
				}
				return tx.RawQuery("update auth.identities set user_id=? where user_id=?", other, id).Exec()
			}))
			require.NotEqual(t, 200, <-result)
			after := r8Count(t, api.db)
			require.Equal(t, before.Users, after.Users)
			expectedIdentities := before.Identities
			if mutation == "delete" {
				expectedIdentities--
			}
			require.Equal(t, expectedIdentities, after.Identities)
			require.Equal(t, before.Sessions, after.Sessions)
			t.Logf("CONCURRENCY users_before=%d users_after=%d identities_before=%d identities_after=%d", before.Users, after.Users, before.Identities, after.Identities)
		})
	}

	t.Run("hook_rejection_rolls_back_session_and_nonce", func(t *testing.T) {
		reset(t)
		wallet := r8NewWallet(t, "ethereum")
		id := r8Seed(t, api, wallet)
		proof := r8Challenge(t, api, wallet, id)
		before := r8Count(t, api.db)
		require.NoError(t, api.db.RawQuery(`create or replace function auth.r8_reject_token(event jsonb) returns jsonb language sql as $$ select '{"error":{"http_code":403,"message":"R8 local rejection"}}'::jsonb $$`).Exec())
		config.Hook.CustomAccessToken.Enabled = true
		config.Hook.CustomAccessToken.URI = "pg-functions://postgres/auth/r8_reject_token"
		require.NoError(t, config.Hook.CustomAccessToken.PopulateExtensibilityPoint())
		// Hook manager resolves URI configuration once per API construction.
		rejectAPI := NewAPIWithVersion(config, api.db, "r8")
		w := r8HTTP(rejectAPI, "/token?grant_type=web3", proof)
		config.Hook.CustomAccessToken.Enabled = false
		require.NotEqual(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "R8 local rejection")
		require.Equal(t, before, r8Count(t, api.db))
		var consumed int
		require.NoError(t, api.db.RawQuery("select count(*) from auth.web3_login_challenges where consumed_at is not null").First(&consumed))
		require.Zero(t, consumed)
		require.Equal(t, 200, r8HTTP(api, "/token?grant_type=web3", proof).Code)
		r8NoCreate(t, before, r8Count(t, api.db))
	})

	t.Run("ordinary_signup_and_login_unchanged", func(t *testing.T) {
		reset(t)
		wallet := r8NewWallet(t, "ethereum")
		id := r8Seed(t, api, wallet)
		before := r8Count(t, api.db)
		now := time.Now().UTC()
		w := r8HTTP(api, "/token?grant_type=web3", r8Proof(t, wallet, "ordinaryloginnonce", now, now.Add(time.Minute), false))
		require.Equal(t, 200, w.Code)
		var response struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		require.Equal(t, id, response.User.ID)
		r8NoCreate(t, before, r8Count(t, api.db))
	})
	t.Run("grant_then_deletion_serializes_after_commit", func(t *testing.T) {
		reset(t)
		wallet := r8NewWallet(t, "ethereum")
		id := r8Seed(t, api, wallet)
		proof := r8Challenge(t, api, wallet, id)
		before := r8Count(t, api.db)
		granted := make(chan int, 1)
		deleted := make(chan error, 1)
		require.NoError(t, api.db.Transaction(func(tx *storage.Connection) error {
			if err := tx.RawQuery("lock table auth.sessions in access exclusive mode").Exec(); err != nil {
				return err
			}
			go func() { granted <- r8HTTP(api, "/token?grant_type=web3", proof).Code }()
			r8WaitLock(t, api.db)
			go func() { deleted <- api.db.RawQuery("delete from auth.identities where user_id=?", id).Exec() }()
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				var count int
				if err := api.db.RawQuery("select count(*) from pg_stat_activity where datname=current_database() and wait_event_type='Lock'").First(&count); err != nil {
					return err
				}
				if count >= 2 {
					return nil
				}
				time.Sleep(10 * time.Millisecond)
			}
			return fmt.Errorf("deletion did not block behind the real issuer identity lock")
		}))
		require.Equal(t, 200, <-granted)
		require.NoError(t, <-deleted)
		after := r8Count(t, api.db)
		require.Equal(t, before.Users, after.Users)
		require.Equal(t, before.Identities-1, after.Identities)
		require.Equal(t, before.Sessions+1, after.Sessions)
		t.Logf("SERIAL_ORDER grant_committed_before_identity_deletion users_before=%d users_after=%d", before.Users, after.Users)
	})
	t.Run("challenge_uuid_mismatch_no_auth_writes", func(t *testing.T) {
		reset(t)
		wallet := r8NewWallet(t, "ethereum")
		r8Seed(t, api, wallet)
		before := r8Count(t, api.db)
		response := r8HTTP(api, "/web3/challenge", map[string]interface{}{"chain": wallet.chain, "address": wallet.address, "chain_id": wallet.chainID, "domain": "example.netlify.com", "uri": "https://example.netlify.com", "expected_user_id": "00000000-0000-0000-0000-000000000001"})
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Equal(t, before, r8Count(t, api.db))
	})
	t.Run("signup_disabled_does_not_disable_existing_only", func(t *testing.T) {
		reset(t)
		wallet := r8NewWallet(t, "ethereum")
		id := r8Seed(t, api, wallet)
		proof := r8Challenge(t, api, wallet, id)
		before := r8Count(t, api.db)
		config.DisableSignup = true
		defer func() { config.DisableSignup = false }()
		require.Equal(t, 200, r8HTTP(api, "/token?grant_type=web3", proof).Code)
		r8NoCreate(t, before, r8Count(t, api.db))
	})

}
