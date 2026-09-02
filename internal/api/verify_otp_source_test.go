package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/supabase/auth/internal/models"
)

func TestMatchesTokenHash(t *testing.T) {
	cases := []struct {
		desc     string
		expected string
		actual   string
		want     bool
	}{
		{"exact match", "abc123", "abc123", true},
		{"pkce prefixed stored hash", "pkce_abc123", "abc123", true},
		{"pkce prefix on the submitted value is not accepted", "abc123", "pkce_abc123", false},
		{"mismatch", "abc123", "def456", false},
		{"empty stored hash never matches an empty submission", "", "", false},
		{"empty stored hash never matches a value", "", "abc123", false},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			assert.Equal(t, c.want, matchesTokenHash(c.expected, c.actual))
		})
	}
}

func TestResolveOtpMatch(t *testing.T) {
	const otpExp = 3600

	now := time.Now()
	stale := now.Add(-2 * time.Hour)

	ott := func(hash string) *models.OneTimeToken {
		return &models.OneTimeToken{TokenHash: hash}
	}

	cases := []struct {
		desc           string
		ott            *models.OneTimeToken
		legacyHash     string
		actual         string
		sentAt         *time.Time
		wantValid      bool
		wantUsedLegacy bool
	}{
		{
			desc:      "row matches",
			ott:       ott("abc123"),
			actual:    "abc123",
			sentAt:    &now,
			wantValid: true,
		},
		{
			desc:      "row matches with pkce prefix",
			ott:       ott("pkce_abc123"),
			actual:    "abc123",
			sentAt:    &now,
			wantValid: true,
		},
		{
			desc:       "row is preferred over the legacy column",
			ott:        ott("abc123"),
			legacyHash: "def456",
			actual:     "abc123",
			sentAt:     &now,
			wantValid:  true,
		},
		{
			// TODO(AUTH-1559): this becomes wantValid false in the follow-up ship.
			desc:           "no row falls back to the legacy column",
			ott:            nil,
			legacyHash:     "abc123",
			actual:         "abc123",
			sentAt:         &now,
			wantValid:      true,
			wantUsedLegacy: true,
		},
		{
			// TODO(AUTH-1559): this becomes wantValid false in the follow-up ship.
			desc:           "stale row falls back to the legacy column",
			ott:            ott("old-hash"),
			legacyHash:     "abc123",
			actual:         "abc123",
			sentAt:         &now,
			wantValid:      true,
			wantUsedLegacy: true,
		},
		{
			desc:       "neither store matches",
			ott:        ott("abc123"),
			legacyHash: "abc123",
			actual:     "def456",
			sentAt:     &now,
		},
		{
			desc:       "expired never matches and never reports a fallback",
			ott:        nil,
			legacyHash: "abc123",
			actual:     "abc123",
			sentAt:     &stale,
		},
		{
			desc:       "nil sentAt never matches",
			ott:        ott("abc123"),
			legacyHash: "abc123",
			actual:     "abc123",
			sentAt:     nil,
		},
		{
			desc:      "empty stored values never match an empty submission",
			ott:       ott(""),
			actual:    "",
			sentAt:    &now,
			wantValid: false,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			valid, usedFallback := resolveOtpMatch(c.ott, c.legacyHash, c.actual, c.sentAt, otpExp)
			assert.Equal(t, c.wantValid, valid, "valid")
			assert.Equal(t, c.wantUsedLegacy, usedFallback, "usedFallback")
		})
	}
}

func TestLegacyUserOtpState(t *testing.T) {
	sentAt := time.Now()

	user := &models.User{
		ConfirmationToken:       "confirmation",
		ConfirmationSentAt:      &sentAt,
		RecoveryToken:           "recovery",
		RecoverySentAt:          &sentAt,
		EmailChangeTokenCurrent: "change-current",
		EmailChangeTokenNew:     "change-new",
		EmailChangeSentAt:       &sentAt,
		PhoneChangeToken:        "phone-change",
		PhoneChangeSentAt:       &sentAt,
		ReauthenticationToken:   "reauthentication",
		ReauthenticationSentAt:  &sentAt,
	}

	cases := []struct {
		tokenType models.OneTimeTokenType
		wantHash  string
	}{
		{models.ConfirmationToken, "confirmation"},
		{models.RecoveryToken, "recovery"},
		{models.EmailChangeTokenCurrent, "change-current"},
		{models.EmailChangeTokenNew, "change-new"},
		{models.PhoneChangeToken, "phone-change"},
		{models.ReauthenticationToken, "reauthentication"},
	}

	for _, c := range cases {
		t.Run(c.tokenType.String(), func(t *testing.T) {
			hash, gotSentAt := legacyUserOtpState(user, c.tokenType)
			assert.Equal(t, c.wantHash, hash)
			assert.Equal(t, &sentAt, gotSentAt)
		})
	}

	t.Run("unknown token type fails closed", func(t *testing.T) {
		hash, gotSentAt := legacyUserOtpState(user, models.OneTimeTokenType(99))
		assert.Equal(t, "", hash)
		assert.Nil(t, gotSentAt)
	})
}
