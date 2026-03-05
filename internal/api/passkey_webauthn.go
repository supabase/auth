package api

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/supabase/auth/internal/models"
)

// getPasskeyWebAuthn creates a *webauthn.WebAuthn instance from the shared server-side WebAuthn configuration.
func (a *API) getPasskeyWebAuthn() (*webauthn.WebAuthn, error) {
	rpConfig := a.config.WebAuthn

	return webauthn.New(&webauthn.Config{
		RPDisplayName:         rpConfig.RPDisplayName,
		RPID:                  rpConfig.RPID,
		RPOrigins:             rpConfig.RPOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// required to support discoverable credentials
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		},
	})
}

// TODO(fm): webAuthnUser is a thin adapter that wraps a *models.User and returns passkey
// credentials (from the webauthn_credentials table) instead of MFA factor
// credentials. This is necessary because the existing User.WebAuthnCredentials()
// method returns MFA WebAuthn factor credentials until they are consolidated.
type webAuthnUser struct {
	user        *models.User
	credentials []webauthn.Credential
}

func newWebAuthnUser(user *models.User, passkeyCredentials []*models.WebAuthnCredential) *webAuthnUser {
	credentials := make([]webauthn.Credential, len(passkeyCredentials))

	for i, pc := range passkeyCredentials {
		credentials[i] = pc.ToWebAuthnCredential()
	}

	return &webAuthnUser{
		user:        user,
		credentials: credentials,
	}
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return u.user.WebAuthnID()
}

func (u *webAuthnUser) WebAuthnName() string {
	if email := u.user.GetEmail(); email != "" {
		return email
	}

	return u.user.GetPhone()
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	if meta := u.user.UserMetaData; meta != nil {
		if name, ok := meta["name"].(string); ok && name != "" {
			return name
		}
	}

	return u.WebAuthnName()
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
