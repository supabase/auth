package api

import (
	"strings"

	"github.com/supabase/auth/internal/api/apierrors"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// verifyUserAndTokenFromOTT is the EnableOTTAsSourceOfTruth path. It finds the
// challenge in the one_time_tokens table and derives the user from that row,
// instead of finding the user by identifier and comparing the users.*_token
// columns. A lookup miss is rejected as an expired or invalid token.
//
// NOTE: Test OTPs and Twilio Verify are not handled yet on this path; a follow-up PR will add them.
func verifyUserAndTokenFromOTT(conn *storage.Connection, params *VerifyParams, aud string) (*models.User, error) {

	// TODO AUTH-1553: Add support for test OTPs and Twilio Verify on this path.
	ott, err := verifyOneTimeToken(conn, params)
	if err != nil {
		return nil, err
	}

	user, err := models.FindUserByID(conn, ott.UserID)
	if models.IsNotFoundError(err) {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Token has expired or is invalid").WithInternalError(err)
	} else if err != nil {
		return nil, apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
	}

	if err := validateUserForOTT(params, ott, user, aud); err != nil {
		return nil, err
	}

	if user.IsBanned() {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeUserBanned, "User is banned")
	}
	return user, nil
}

func verifyOneTimeToken(conn *storage.Connection, params *VerifyParams) (*models.OneTimeToken, error) {
	tokenTypes := verifyTypeToTokenTypes(params.Type)
	if len(tokenTypes) == 0 {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Token has expired or is invalid").WithInternalMessage("unknown verification type")
	}

	ott, err := models.FindOneTimeTokenWithPKCEFallback(conn, params.TokenHash, tokenTypes...)
	if models.IsNotFoundError(err) {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Token has expired or is invalid").WithInternalMessage("one time token not found")
	} else if err != nil {
		return nil, apierrors.NewInternalServerError("Database error finding one time token").WithInternalError(err)
	}

	if ott.IsExpired() {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Token has expired or is invalid").WithInternalMessage("one time token has expired")
	}

	// The generic email type needs to match to the flow that issues the token, so the caller runs the right post-verify step
	if params.Type == mail.EmailOTPVerification {
		switch ott.TokenType {
		case models.ConfirmationToken:
			params.Type = mail.SignupVerification
		case models.RecoveryToken:
			params.Type = mail.MagicLinkVerification
		}
	}

	return ott, nil
}

func verifyTypeToTokenTypes(verifyType string) []models.OneTimeTokenType {
	switch verifyType {
	case mail.EmailOTPVerification:
		return []models.OneTimeTokenType{models.ConfirmationToken, models.RecoveryToken}
	case mail.SignupVerification, mail.InviteVerification:
		return []models.OneTimeTokenType{models.ConfirmationToken}
	case mail.RecoveryVerification, mail.MagicLinkVerification:
		return []models.OneTimeTokenType{models.RecoveryToken}
	case mail.EmailChangeVerification:
		return []models.OneTimeTokenType{models.EmailChangeTokenCurrent, models.EmailChangeTokenNew}
	case phoneChangeVerification:
		return []models.OneTimeTokenType{models.PhoneChangeToken}
	case smsVerification:
		return []models.OneTimeTokenType{models.ConfirmationToken}
	default:
		return nil
	}
}

// validateUserForOTT checks that the user found from a one_time_tokens row is
// the one the request is entitled to act on.
//
// The legacy path gets these guarantees for free from its identifier-keyed lookups (which also filter on
// aud and is_sso_user), so a mismatch there is a not-found.
//
// The one_time_tokens path finds the user by token hash, so it has to check the binding itself.
func validateUserForOTT(params *VerifyParams, ott *models.OneTimeToken, user *models.User, aud string) error {
	mismatch := apierrors.NewForbiddenError(apierrors.ErrorCodeOTPExpired, "Token has expired or is invalid")

	if user.IsSSOUser {
		return mismatch.WithInternalMessage("SSO users cannot be verified with one time tokens")
	}

	if user.Aud != aud {
		return mismatch.WithInternalMessage("user audience does not match")
	}

	switch params.Type {
	case smsVerification:
		if params.Phone == "" || user.GetPhone() != params.Phone {
			return mismatch.WithInternalMessage("user phone does not match")
		}
	case phoneChangeVerification:
		if params.Phone == "" || user.PhoneChange != params.Phone {
			return mismatch.WithInternalMessage("user phone does not match")
		}
	case mail.EmailChangeVerification:
		expected := user.EmailChange
		if ott.TokenType == models.EmailChangeTokenCurrent {
			expected = user.GetEmail()
		}
		if params.Email == "" || !strings.EqualFold(expected, params.Email) {
			return mismatch.WithInternalMessage("user email does not match")
		}
	default: // Signup, Invite, Recovery, MagicLink
		if params.Email == "" || !strings.EqualFold(user.GetEmail(), params.Email) {
			return mismatch.WithInternalMessage("user email does not match")
		}
	}
	return nil
}
