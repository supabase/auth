package models

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// allAuditActions lists every AuditAction declared in this package. Keep it in
// sync when adding a new action, so the tests below can assert that the action
// is fully wired up.
var allAuditActions = []AuditAction{
	LoginAction,
	LogoutAction,
	InviteAcceptedAction,
	UserSignedUpAction,
	UserInvitedAction,
	UserDeletedAction,
	UserModifiedAction,
	UserRecoveryRequestedAction,
	UserReauthenticateAction,
	UserConfirmationRequestedAction,
	UserRepeatedSignUpAction,
	UserUpdatePasswordAction,
	TokenRevokedAction,
	TokenRefreshedAction,
	EnrollFactorAction,
	UnenrollFactorAction,
	CreateChallengeAction,
	VerifyFactorAction,
	DeleteFactorAction,
	UpdateFactorAction,
	IdentityUnlinkAction,
	PasskeyCreatedAction,
	PasskeyUpdatedAction,
	PasskeyDeletedAction,
}

// A missing entry in ActionLogTypeMap is silent: NewAuditLogEntry looks the
// action up with a map index, so an unmapped action is persisted with an empty
// log_type instead of failing loudly.
func TestActionLogTypeMapCoversAllActions(t *testing.T) {
	for _, action := range allAuditActions {
		t.Run(string(action), func(t *testing.T) {
			logType, ok := ActionLogTypeMap[action]
			require.True(t, ok, "action %q has no entry in ActionLogTypeMap", action)
			require.NotEmpty(t, logType, "action %q maps to an empty log_type", action)
		})
	}
}

func TestActionLogTypeMapHasNoUnknownActions(t *testing.T) {
	known := make(map[AuditAction]bool, len(allAuditActions))
	for _, action := range allAuditActions {
		known[action] = true
	}

	for action := range ActionLogTypeMap {
		require.True(t, known[action], "ActionLogTypeMap contains unknown action %q, add it to allAuditActions", action)
	}
}
