package api

import (
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// oauthVerifiedEmail returns the lowercase provider email when identity_data
// contains a non-empty email and email_verified == true. Missing or non-bool
// verification claims are treated as unverified. Mailer.Autoconfirm is not
// consulted: that flag is for linking/signup, not trusting a changed address.
func oauthVerifiedEmail(identity *models.Identity) (string, bool) {
	if identity == nil || identity.IdentityData == nil {
		return "", false
	}
	email, ok := identity.IdentityData["email"].(string)
	if !ok {
		return "", false
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", false
	}
	if !identity.IsEmailVerified() {
		return "", false
	}
	return email, true
}

// syncOAuthUserEmail optionally copies a changed, verified OAuth email onto
// auth.users.email for an already-linked identity.
//
// Policy skips (login still succeeds; identity metadata has already been
// refreshed):
//   - provider SyncEmail is false or the provider has no env config
//   - provider email is missing or not attested as verified
//   - new email equals the current canonical email (after lowercasing)
//   - the user has an independent provider=email identity
//   - the canonical email is not owned by this identity (users.email does not
//     match the identity's previous email)
//   - the new address already belongs to another user in the default linking
//     domain (no implicit merge or identity transfer)
//
// Unexpected database errors are returned; uniqueness conflicts are skipped.
func (a *API) syncOAuthUserEmail(tx *storage.Connection, r *http.Request, user *models.User, identity *models.Identity, previousIdentityEmail, providerType string) error {
	pConfig, ok := a.config.External.OAuthConfig(providerType)
	if !ok || !pConfig.SyncEmail {
		return nil
	}

	newEmail, verified := oauthVerifiedEmail(identity)
	if !verified {
		return nil
	}

	currentEmail := strings.ToLower(strings.TrimSpace(user.GetEmail()))
	if currentEmail == newEmail {
		return nil
	}

	if _, terr := models.FindIdentityByIdAndProvider(tx, user.ID.String(), EmailProvider); terr == nil {
		// Any email identity is treated as an independent password / magic-link
		// / OTP credential. There is no reliable marker that it only mirrors
		// the OAuth-created address, so do not replace users.email.
		return nil
	} else if !models.IsNotFoundError(terr) {
		return terr
	}

	previousEmail := strings.ToLower(strings.TrimSpace(previousIdentityEmail))
	if previousEmail == "" || previousEmail != currentEmail {
		// Canonical email is empty or comes from another source (admin update,
		// a different linked identity, etc.).
		return nil
	}

	duplicate, terr := models.IsDuplicatedEmail(tx, newEmail, user.Aud, user, a.config.Experimental.ProviderLinkingDomains)
	if terr != nil {
		return terr
	}
	if duplicate != nil && duplicate.ID != user.ID {
		// Collision: keep this user's canonical email, continue the OAuth
		// login, and leave the other account untouched.
		observability.GetLogEntry(r).Entry.WithFields(logrus.Fields{
			"user_id":     user.ID,
			"provider":    providerType,
			"provider_id": identity.ProviderID,
		}).Info("skipping OAuth email sync because the new email belongs to another user")
		return nil
	}

	// When updating the email make sure unique violation does not error the login, dupe check above should have caught this,
	// but better safe than sorry.
	if terr := user.SetEmail(tx, newEmail); terr != nil {
		if pgErr := utilities.NewPostgresError(terr); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
			observability.GetLogEntry(r).Entry.WithFields(logrus.Fields{
				"user_id":     user.ID,
				"provider":    providerType,
				"provider_id": identity.ProviderID,
			}).Info("skipping OAuth email sync because the new email violates uniqueness")
			return nil
		}
		return terr
	}

	if terr := user.ClearAllPendingTokens(tx); terr != nil {
		return terr
	}

	if terr := models.NewAuditLogEntry(a.config.AuditLog, r, tx, user, models.UserModifiedAction, utilities.GetIPAddress(r), map[string]any{
		"provider":  providerType,
		"old_email": currentEmail,
		"new_email": newEmail,
	}); terr != nil {
		return terr
	}

	return nil
}
