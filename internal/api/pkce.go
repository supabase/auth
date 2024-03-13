package api

import (
	"regexp"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

const (
	PKCEPrefix                    = "pkce_"
	MinCodeChallengeLength        = 43
	MaxCodeChallengeLength        = 128
	InvalidPKCEParamsErrorMessage = "PKCE flow requires code_challenge_method and code_challenge"
)

var codeChallengePattern = regexp.MustCompile("^[a-zA-Z._~0-9-]+$")

func isValidCodeChallenge(codeChallenge string) (bool, error) {
	// See RFC 7636 Section 4.2: https://www.rfc-editor.org/rfc/rfc7636#section-4.2
	switch codeChallengeLength := len(codeChallenge); {
	case codeChallengeLength < MinCodeChallengeLength, codeChallengeLength > MaxCodeChallengeLength:
		return false, badRequestError(ErrorCodeValidationFailed, "code challenge has to be between %v and %v characters", MinCodeChallengeLength, MaxCodeChallengeLength)
	case !codeChallengePattern.MatchString(codeChallenge):
		return false, badRequestError(ErrorCodeValidationFailed, "code challenge can only contain alphanumeric characters, hyphens, periods, underscores and tildes")
	default:
		return true, nil
	}
}

func addFlowPrefixToToken(token string, flowType models.FlowType) string {
	if isPKCEFlow(flowType) {
		return flowType.String() + "_" + token
	} else if isImplicitFlow(flowType) {
		return token
	}
	return token
}

func issueAuthCode(tx *storage.Connection, user *models.User, authenticationMethod models.AuthenticationMethod) (string, error) {
	flowState, err := models.FindFlowStateByUserID(tx, user.ID.String(), authenticationMethod)
	if err != nil && models.IsNotFoundError(err) {
		return "", unprocessableEntityError(ErrorCodeFlowStateNotFound, "No valid flow state found for user.")
	} else if err != nil {
		return "", err
	}
	if err := flowState.RecordAuthCodeIssuedAtTime(tx); err != nil {
		return "", err
	}

	return flowState.AuthCode, nil
}

func isPKCEFlow(flowType models.FlowType) bool {
	return flowType == models.PKCEFlow
}

func isImplicitFlow(flowType models.FlowType) bool {
	return flowType == models.ImplicitFlow
}

func validatePKCEParams(codeChallengeMethod, codeChallenge string) error {
	switch true {
	case (codeChallenge == "") != (codeChallengeMethod == ""):
		return badRequestError(ErrorCodeValidationFailed, InvalidPKCEParamsErrorMessage)
	case codeChallenge != "":
		if valid, err := isValidCodeChallenge(codeChallenge); !valid {
			return err
		}
	default:
		// if both params are empty, just return nil
		return nil
	}
	return nil
}

func getFlowFromChallenge(codeChallenge string) models.FlowType {
	if codeChallenge != "" {
		return models.PKCEFlow
	} else {
		return models.ImplicitFlow
	}
}

// Should only be used with Auth Code of PKCE Flows
func generateFlowState(tx *storage.Connection, providerType string, authenticationMethod models.AuthenticationMethod, codeChallengeMethodParam string, codeChallenge string, userID *uuid.UUID) (*models.FlowState, error) {
	codeChallengeMethod, err := models.ParseCodeChallengeMethod(codeChallengeMethodParam)
	if err != nil {
		return nil, err
	}
	flowState := models.NewFlowState(providerType, codeChallenge, codeChallengeMethod, authenticationMethod, userID)
	if err := tx.Create(flowState); err != nil {
		return nil, err
	}
	return flowState, nil

}
