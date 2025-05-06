package mailer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type MailRequest struct {
	To              string
	SubjectTemplate string
	TemplateURL     string
	DefaultTemplate string
	TemplateData    map[string]interface{}
	Headers         map[string][]string
	Type            string
}

type MailClient interface {
	Mail(
		ctx context.Context,
		to string,
		subjectTemplate string,
		templateURL string,
		defaultTemplate string,
		templateData map[string]interface{},
		headers map[string][]string,
		typ string,
	) error
}

// TemplateMailer will send mail and use templates from the site for easy mail styling
type TemplateMailer struct {
	SiteURL string
	Config  *conf.GlobalConfiguration
	Mailer  MailClient
}

func encodeRedirectURL(referrerURL string) string {
	if len(referrerURL) > 0 {
		if strings.ContainsAny(referrerURL, "&=#") {
			// if the string contains &, = or # it has not been URL
			// encoded by the caller, which means it should be URL
			// encoded by us otherwise, it should be taken as-is
			referrerURL = url.QueryEscape(referrerURL)
		}
	}
	return referrerURL
}

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

const defaultInviteMail = `<h2>You have been invited</h2>

<p>You have been invited to create a user on {{ .SiteURL }}. Follow this link to accept the invite:</p>
<p><a href="{{ .ConfirmationURL }}">Accept the invite</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

const defaultConfirmationMail = `<h2>Confirm your email</h2>

<p>Follow this link to confirm your email:</p>
<p><a href="{{ .ConfirmationURL }}">Confirm your email address</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>
`

const defaultRecoveryMail = `<h2>Reset password</h2>

<p>Follow this link to reset the password for your user:</p>
<p><a href="{{ .ConfirmationURL }}">Reset password</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

const defaultMagicLinkMail = `<h2>Magic Link</h2>

<p>Follow this link to login:</p>
<p><a href="{{ .ConfirmationURL }}">Log In</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

const defaultEmailChangeMail = `<h2>Confirm email address change</h2>

<p>Follow this link to confirm the update of your email address from {{ .Email }} to {{ .NewEmail }}:</p>
<p><a href="{{ .ConfirmationURL }}">Change email address</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

const defaultReauthenticateMail = `<h2>Confirm reauthentication</h2>

<p>Enter the code: {{ .Token }}</p>`

func (m *TemplateMailer) Headers(messageType string) map[string][]string {
	originalHeaders := m.Config.SMTP.NormalizedHeaders()

	if originalHeaders == nil {
		return nil
	}

	headers := make(map[string][]string, len(originalHeaders))

	for header, values := range originalHeaders {
		replacedValues := make([]string, 0, len(values))

		if header == "" {
			continue
		}

		for _, value := range values {
			if value == "" {
				continue
			}

			// TODO: in the future, use a templating engine to add more contextual data available to headers
			if strings.Contains(value, "$messageType") {
				replacedValues = append(replacedValues, strings.ReplaceAll(value, "$messageType", messageType))
			} else {
				replacedValues = append(replacedValues, value)
			}
		}

		headers[header] = replacedValues
	}

	return headers
}

// InviteMail sends a invite mail to a new user
func (m *TemplateMailer) InviteMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	path, err := getPath(m.Config.Mailer.URLPaths.Invite, &EmailParams{
		Token:      user.ConfirmationToken,
		Type:       "invite",
		RedirectTo: referrerURL,
	})

	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.ConfirmationToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}

	return m.Mailer.Mail(
		r.Context(),
		user.GetEmail(),
		withDefault(m.Config.Mailer.Subjects.Invite, "You have been invited"),
		m.Config.Mailer.Templates.Invite,
		defaultInviteMail,
		data,
		m.Headers("invite"),
		"invite",
	)
}

// ConfirmationMail sends a signup confirmation mail to a new user
func (m *TemplateMailer) ConfirmationMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	path, err := getPath(m.Config.Mailer.URLPaths.Confirmation, &EmailParams{
		Token:      user.ConfirmationToken,
		Type:       "signup",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.ConfirmationToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}

	return m.Mailer.Mail(
		r.Context(),
		user.GetEmail(),
		withDefault(m.Config.Mailer.Subjects.Confirmation, "Confirm Your Email"),
		m.Config.Mailer.Templates.Confirmation,
		defaultConfirmationMail,
		data,
		m.Headers("confirm"),
		"confirm",
	)
}

// ReauthenticateMail sends a reauthentication mail to an authenticated user
func (m *TemplateMailer) ReauthenticateMail(r *http.Request, user *models.User, otp string) error {
	data := map[string]interface{}{
		"SiteURL": m.Config.SiteURL,
		"Email":   user.Email,
		"Token":   otp,
		"Data":    user.UserMetaData,
	}

	return m.Mailer.Mail(
		r.Context(),
		user.GetEmail(),
		withDefault(m.Config.Mailer.Subjects.Reauthentication, "Confirm reauthentication"),
		m.Config.Mailer.Templates.Reauthentication,
		defaultReauthenticateMail,
		data,
		m.Headers("reauthenticate"),
		"reauthenticate",
	)
}

// EmailChangeMail sends an email change confirmation mail to a user
func (m *TemplateMailer) EmailChangeMail(r *http.Request, user *models.User, otpNew, otpCurrent, referrerURL string, externalURL *url.URL) error {
	type Email struct {
		Address   string
		Otp       string
		TokenHash string
		Subject   string
		Template  string
	}
	emails := []Email{
		{
			Address:   user.EmailChange,
			Otp:       otpNew,
			TokenHash: user.EmailChangeTokenNew,
			Subject:   withDefault(m.Config.Mailer.Subjects.EmailChange, "Confirm Email Change"),
			Template:  m.Config.Mailer.Templates.EmailChange,
		},
	}

	currentEmail := user.GetEmail()
	if m.Config.Mailer.SecureEmailChangeEnabled && currentEmail != "" {
		emails = append(emails, Email{
			Address:   currentEmail,
			Otp:       otpCurrent,
			TokenHash: user.EmailChangeTokenCurrent,
			Subject:   withDefault(m.Config.Mailer.Subjects.Confirmation, "Confirm Email Address"),
			Template:  m.Config.Mailer.Templates.EmailChange,
		})
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	errors := make(chan error, len(emails))
	for _, email := range emails {
		path, err := getPath(
			m.Config.Mailer.URLPaths.EmailChange,
			&EmailParams{
				Token:      email.TokenHash,
				Type:       "email_change",
				RedirectTo: referrerURL,
			},
		)
		if err != nil {
			return err
		}
		go func(address, token, tokenHash, template string) {
			data := map[string]interface{}{
				"SiteURL":         m.Config.SiteURL,
				"ConfirmationURL": externalURL.ResolveReference(path).String(),
				"Email":           user.GetEmail(),
				"NewEmail":        user.EmailChange,
				"Token":           token,
				"TokenHash":       tokenHash,
				"SendingTo":       address,
				"Data":            user.UserMetaData,
				"RedirectTo":      referrerURL,
			}
			errors <- m.Mailer.Mail(
				ctx,
				address,
				withDefault(m.Config.Mailer.Subjects.EmailChange, "Confirm Email Change"),
				template,
				defaultEmailChangeMail,
				data,
				m.Headers("email_change"),
				"email_change",
			)
		}(email.Address, email.Otp, email.TokenHash, email.Template)
	}

	for i := 0; i < len(emails); i++ {
		e := <-errors
		if e != nil {
			return e
		}
	}
	return nil
}

// RecoveryMail sends a password recovery mail
func (m *TemplateMailer) RecoveryMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	path, err := getPath(m.Config.Mailer.URLPaths.Recovery, &EmailParams{
		Token:      user.RecoveryToken,
		Type:       "recovery",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}
	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.RecoveryToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}

	return m.Mailer.Mail(
		r.Context(),
		user.GetEmail(),
		withDefault(m.Config.Mailer.Subjects.Recovery, "Reset Your Password"),
		m.Config.Mailer.Templates.Recovery,
		defaultRecoveryMail,
		data,
		m.Headers("recovery"),
		"recovery",
	)
}

// MagicLinkMail sends a login link mail
func (m *TemplateMailer) MagicLinkMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	path, err := getPath(m.Config.Mailer.URLPaths.Recovery, &EmailParams{
		Token:      user.RecoveryToken,
		Type:       "magiclink",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}

	data := map[string]interface{}{
		"SiteURL":         m.Config.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.RecoveryToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}

	return m.Mailer.Mail(
		r.Context(),
		user.GetEmail(),
		withDefault(m.Config.Mailer.Subjects.MagicLink, "Your Magic Link"),
		m.Config.Mailer.Templates.MagicLink,
		defaultMagicLinkMail,
		data,
		m.Headers("magiclink"),
		"magiclink",
	)
}

// GetEmailActionLink returns a magiclink, recovery or invite link based on the actionType passed.
func (m TemplateMailer) GetEmailActionLink(user *models.User, actionType, referrerURL string, externalURL *url.URL) (string, error) {
	var err error
	var path *url.URL

	switch actionType {
	case "magiclink":
		path, err = getPath(m.Config.Mailer.URLPaths.Recovery, &EmailParams{
			Token:      user.RecoveryToken,
			Type:       "magiclink",
			RedirectTo: referrerURL,
		})
	case "recovery":
		path, err = getPath(m.Config.Mailer.URLPaths.Recovery, &EmailParams{
			Token:      user.RecoveryToken,
			Type:       "recovery",
			RedirectTo: referrerURL,
		})
	case "invite":
		path, err = getPath(m.Config.Mailer.URLPaths.Invite, &EmailParams{
			Token:      user.ConfirmationToken,
			Type:       "invite",
			RedirectTo: referrerURL,
		})
	case "signup":
		path, err = getPath(m.Config.Mailer.URLPaths.Confirmation, &EmailParams{
			Token:      user.ConfirmationToken,
			Type:       "signup",
			RedirectTo: referrerURL,
		})
	case "email_change_current":
		path, err = getPath(m.Config.Mailer.URLPaths.EmailChange, &EmailParams{
			Token:      user.EmailChangeTokenCurrent,
			Type:       "email_change",
			RedirectTo: referrerURL,
		})
	case "email_change_new":
		path, err = getPath(m.Config.Mailer.URLPaths.EmailChange, &EmailParams{
			Token:      user.EmailChangeTokenNew,
			Type:       "email_change",
			RedirectTo: referrerURL,
		})
	default:
		return "", fmt.Errorf("invalid email action link type: %s", actionType)
	}
	if err != nil {
		return "", err
	}
	return externalURL.ResolveReference(path).String(), nil
}
