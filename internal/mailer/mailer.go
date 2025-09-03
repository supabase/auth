package mailer

import (
	"context"
	"net/http"
	"net/url"

	"github.com/supabase/auth/internal/models"
)

const (
	SignupVerification             = "signup"
	RecoveryVerification           = "recovery"
	InviteVerification             = "invite"
	MagicLinkVerification          = "magiclink"
	EmailChangeVerification        = "email_change"
	EmailOTPVerification           = "email"
	EmailChangeCurrentVerification = "email_change_current"
	EmailChangeNewVerification     = "email_change_new"
	ReauthenticationVerification   = "reauthentication"
)

// Mailer defines the interface a mailer must implement.
type Mailer interface {
	InviteMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error
	ConfirmationMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error
	RecoveryMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error
	MagicLinkMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error
	EmailChangeMail(r *http.Request, user *models.User, otpNew, otpCurrent, referrerURL string, externalURL *url.URL) error
	ReauthenticateMail(r *http.Request, user *models.User, otp string) error
	GetEmailActionLink(user *models.User, actionType, referrerURL string, externalURL *url.URL) (string, error)
}

type Client interface {
	Mail(
		ctx context.Context,
		to string,
		subjectTemplate string,
		templateURL string,
		defaultTemplate string,
		templateData map[string]any,
		headers map[string][]string,
		typ string,
	) error
}

type EmailData struct {
	Token           string `json:"token"`
	TokenHash       string `json:"token_hash"`
	RedirectTo      string `json:"redirect_to"`
	EmailActionType string `json:"email_action_type"`
	SiteURL         string `json:"site_url"`
	TokenNew        string `json:"token_new"`
	TokenHashNew    string `json:"token_hash_new"`
}
