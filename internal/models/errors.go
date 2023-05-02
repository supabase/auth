package models

// IsNotFoundError returns whether an error represents a "not found" error.
func IsNotFoundError(err error) bool {
	switch err.(type) {
	case UserNotFoundError, *UserNotFoundError:
		return true
	case SessionNotFoundError, *SessionNotFoundError:
		return true
	case ConfirmationTokenNotFoundError, *ConfirmationTokenNotFoundError:
		return true
	case RefreshTokenNotFoundError, *RefreshTokenNotFoundError:
		return true
	case IdentityNotFoundError, *IdentityNotFoundError:
		return true
	case ChallengeNotFoundError, *ChallengeNotFoundError:
		return true
	case FactorNotFoundError, *FactorNotFoundError:
		return true
	case SSOProviderNotFoundError, *SSOProviderNotFoundError:
		return true
	case SAMLRelayStateNotFoundError, *SAMLRelayStateNotFoundError:
		return true
	case FlowStateNotFoundError, *FlowStateNotFoundError:
		return true
	}
	return false
}

type SessionNotFoundError struct{}

func (e SessionNotFoundError) Error() string {
	return "Session not found"
}

// UserNotFoundError represents when a user is not found.
type UserNotFoundError struct{}

func (e UserNotFoundError) Error() string {
	return "User not found"
}

// IdentityNotFoundError represents when an identity is not found.
type IdentityNotFoundError struct{}

func (e IdentityNotFoundError) Error() string {
	return "Identity not found"
}

// ConfirmationTokenNotFoundError represents when a confirmation token is not found.
type ConfirmationTokenNotFoundError struct{}

func (e ConfirmationTokenNotFoundError) Error() string {
	return "Confirmation Token not found"
}

// RefreshTokenNotFoundError represents when a refresh token is not found.
type RefreshTokenNotFoundError struct{}

func (e RefreshTokenNotFoundError) Error() string {
	return "Refresh Token not found"
}

// FactorNotFoundError represents when a user is not found.
type FactorNotFoundError struct{}

func (e FactorNotFoundError) Error() string {
	return "Factor not found"
}

// ChallengeNotFoundError represents when a user is not found.
type ChallengeNotFoundError struct{}

func (e ChallengeNotFoundError) Error() string {
	return "Challenge not found"
}

// SSOProviderNotFoundError represents an error when a SSO Provider can't be
// found.
type SSOProviderNotFoundError struct{}

func (e SSOProviderNotFoundError) Error() string {
	return "SSO Identity Provider not found"
}

// SAMLRelayStateNotFoundError represents an error when a SAML relay state
// can't be found.
type SAMLRelayStateNotFoundError struct{}

func (e SAMLRelayStateNotFoundError) Error() string {
	return "SAML RelayState not found"
}

// FlowStateNotFoundError represents an error when an FlowState can't be
// found.
type FlowStateNotFoundError struct{}

func (e FlowStateNotFoundError) Error() string {
	return "Flow State not found"
}
