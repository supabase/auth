package api

import (
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
	"regexp"
	"time"
)

const PKCE = "pkce"

const MinCodeChallengeLength = 43
const MaxCodeChallengeLength = 128

var codeChallengePattern = regexp.MustCompile("^[a-zA-Z-._~0-9]+$")

func isValidCodeChallenge(codeChallenge string) (bool, error) {
	// See RFC 7636 Section 4.2: https://www.rfc-editor.org/rfc/rfc7636#section-4.2
	hasValidChallengeChars := codeChallengePattern.MatchString
	switch codeChallengeLength := len(codeChallenge); {
	case codeChallengeLength < MinCodeChallengeLength, codeChallengeLength > MaxCodeChallengeLength:
		return false, badRequestError("code challenge has to be between %v and %v characters", MinCodeChallengeLength, MaxCodeChallengeLength)
	case !hasValidChallengeChars(codeChallenge):
		return false, badRequestError("code challenge can only contain alphanumeric characters, hyphens, periods, underscores and tildes")
	default:
		return true, nil
	}
}

func addFlowPrefixToToken(token string, flowType models.FlowType) string {
	if flowType == models.PKCEFlow {
		return models.PKCEFlow.String() + "_" + token
	} else if flowType == models.ImplicitFlow {
		return token
	}
	return token
}

func issueAuthCode(tx *storage.Connection, user *models.User, expiryDuration time.Duration) (string, error) {
	flowState, err := models.FindFlowStateByUserID(tx, user.ID.String())
	if models.IsNotFoundError(err) {
		return "", badRequestError("No valid flow state found for user.")
	} else if err != nil {
		return "", err
	}

	if flowState.IsExpired(expiryDuration) {
		return "", badRequestError("Flow state is expired")
	}
	return flowState.AuthCode, nil
}
