package templatemailer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

const (
	InviteTemplate           = "invite"
	ConfirmationTemplate     = "confirmation"
	RecoveryTemplate         = "recovery"
	EmailChangeTemplate      = "email_change"
	MagicLinkTemplate        = "magic_link"
	ReauthenticationTemplate = "reauthentication"
)

const defaultInviteMail = `<h2>You have been invited</h2>

<p>You have been invited to create a user on {{ .SiteURL }}. Follow this link to accept the invite:</p>
<p><a href="{{ .ConfirmationURL }}">Accept the invite</a></p>
<p>Alternatively, enter the code: {{ .Token }}</p>`

const defaultConfirmationMail = `<h2>Confirm Your Email</h2>

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

var (
	templateTypes = []string{
		InviteTemplate,
		ConfirmationTemplate,
		RecoveryTemplate,
		EmailChangeTemplate,
		MagicLinkTemplate,
		ReauthenticationTemplate,
	}
	defaultTemplateSubjects = &conf.EmailContentConfiguration{
		Invite:           "You have been invited",
		Confirmation:     "Confirm Your Email",
		Recovery:         "Reset Your Password",
		MagicLink:        "Your Magic Link",
		EmailChange:      "Confirm Email Change",
		Reauthentication: "Confirm reauthentication",
	}
	defaultTemplateBodies = &conf.EmailContentConfiguration{
		Invite:           defaultInviteMail,
		Confirmation:     defaultConfirmationMail,
		Recovery:         defaultRecoveryMail,
		MagicLink:        defaultMagicLinkMail,
		EmailChange:      defaultEmailChangeMail,
		Reauthentication: defaultReauthenticateMail,
	}
)

func (m *Mailer) Headers(cfg *conf.GlobalConfiguration, messageType string) map[string][]string {
	originalHeaders := cfg.SMTP.NormalizedHeaders()

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
func (m *Mailer) InviteMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	cfg := m.getConfig()
	path, err := getPath(cfg.Mailer.URLPaths.Invite, &emailParams{
		Token:      user.ConfirmationToken,
		Type:       "invite",
		RedirectTo: referrerURL,
	})

	if err != nil {
		return err
	}

	data := map[string]any{
		"SiteURL":         cfg.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.ConfirmationToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}
	return m.mail(r.Context(), cfg, InviteTemplate, user.GetEmail(), data)
}

// ConfirmationMail sends a signup confirmation mail to a new user
func (m *Mailer) ConfirmationMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	cfg := m.getConfig()
	path, err := getPath(cfg.Mailer.URLPaths.Confirmation, &emailParams{
		Token:      user.ConfirmationToken,
		Type:       "signup",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}

	data := map[string]any{
		"SiteURL":         cfg.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.ConfirmationToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}
	return m.mail(r.Context(), cfg, ConfirmationTemplate, user.GetEmail(), data)
}

// ReauthenticateMail sends a reauthentication mail to an authenticated user
func (m *Mailer) ReauthenticateMail(r *http.Request, user *models.User, otp string) error {
	cfg := m.getConfig()
	data := map[string]any{
		"SiteURL": cfg.SiteURL,
		"Email":   user.Email,
		"Token":   otp,
		"Data":    user.UserMetaData,
	}
	return m.mail(r.Context(), cfg, ReauthenticationTemplate, user.GetEmail(), data)
}

// EmailChangeMail sends an email change confirmation mail to a user
func (m *Mailer) EmailChangeMail(r *http.Request, user *models.User, otpNew, otpCurrent, referrerURL string, externalURL *url.URL) error {
	type Email struct {
		Action    string
		Address   string
		Otp       string
		TokenHash string
	}
	emails := []Email{
		{
			Address:   user.EmailChange,
			Otp:       otpNew,
			TokenHash: user.EmailChangeTokenNew,
		},
	}

	cfg := m.getConfig()
	currentEmail := user.GetEmail()
	if cfg.Mailer.SecureEmailChangeEnabled && currentEmail != "" {
		emails = append(emails, Email{
			Address:   currentEmail,
			Otp:       otpCurrent,
			TokenHash: user.EmailChangeTokenCurrent,
		})
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	errors := make(chan error, len(emails))
	for _, email := range emails {
		path, err := getPath(
			cfg.Mailer.URLPaths.EmailChange,
			&emailParams{
				Token:      email.TokenHash,
				Type:       "email_change",
				RedirectTo: referrerURL,
			},
		)
		if err != nil {
			return err
		}
		go func(address, token, tokenHash string) {
			data := map[string]any{
				"SiteURL":         cfg.SiteURL,
				"ConfirmationURL": externalURL.ResolveReference(path).String(),
				"Email":           user.GetEmail(),
				"NewEmail":        user.EmailChange,
				"Token":           token,
				"TokenHash":       tokenHash,
				"SendingTo":       address,
				"Data":            user.UserMetaData,
				"RedirectTo":      referrerURL,
			}
			errors <- m.mail(
				ctx,
				cfg,
				EmailChangeTemplate,
				address,
				data,
			)
		}(email.Address, email.Otp, email.TokenHash)
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
func (m *Mailer) RecoveryMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	cfg := m.getConfig()
	path, err := getPath(cfg.Mailer.URLPaths.Recovery, &emailParams{
		Token:      user.RecoveryToken,
		Type:       "recovery",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}
	data := map[string]any{
		"SiteURL":         cfg.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.RecoveryToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}
	return m.mail(r.Context(), cfg, RecoveryTemplate, user.GetEmail(), data)
}

// MagicLinkMail sends a login link mail
func (m *Mailer) MagicLinkMail(r *http.Request, user *models.User, otp, referrerURL string, externalURL *url.URL) error {
	cfg := m.getConfig()
	path, err := getPath(cfg.Mailer.URLPaths.Recovery, &emailParams{
		Token:      user.RecoveryToken,
		Type:       "magiclink",
		RedirectTo: referrerURL,
	})
	if err != nil {
		return err
	}

	data := map[string]any{
		"SiteURL":         cfg.SiteURL,
		"ConfirmationURL": externalURL.ResolveReference(path).String(),
		"Email":           user.Email,
		"Token":           otp,
		"TokenHash":       user.RecoveryToken,
		"Data":            user.UserMetaData,
		"RedirectTo":      referrerURL,
	}
	return m.mail(r.Context(), cfg, MagicLinkTemplate, user.GetEmail(), data)
}

// GetEmailActionLink returns a magiclink, recovery or invite link based on the actionType passed.
func (m *Mailer) GetEmailActionLink(user *models.User, actionType, referrerURL string, externalURL *url.URL) (string, error) {
	var err error
	var path *url.URL

	cfg := m.getConfig()
	switch actionType {
	case "magiclink":
		path, err = getPath(cfg.Mailer.URLPaths.Recovery, &emailParams{
			Token:      user.RecoveryToken,
			Type:       "magiclink",
			RedirectTo: referrerURL,
		})
	case "recovery":
		path, err = getPath(cfg.Mailer.URLPaths.Recovery, &emailParams{
			Token:      user.RecoveryToken,
			Type:       "recovery",
			RedirectTo: referrerURL,
		})
	case "invite":
		path, err = getPath(cfg.Mailer.URLPaths.Invite, &emailParams{
			Token:      user.ConfirmationToken,
			Type:       "invite",
			RedirectTo: referrerURL,
		})
	case "signup":
		path, err = getPath(cfg.Mailer.URLPaths.Confirmation, &emailParams{
			Token:      user.ConfirmationToken,
			Type:       "signup",
			RedirectTo: referrerURL,
		})
	case "email_change_current":
		path, err = getPath(cfg.Mailer.URLPaths.EmailChange, &emailParams{
			Token:      user.EmailChangeTokenCurrent,
			Type:       "email_change",
			RedirectTo: referrerURL,
		})
	case "email_change_new":
		path, err = getPath(cfg.Mailer.URLPaths.EmailChange, &emailParams{
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

type emailParams struct {
	Token      string
	Type       string
	RedirectTo string
}

func getPath(filepath string, params *emailParams) (*url.URL, error) {
	path := &url.URL{}
	if filepath != "" {
		if p, err := url.Parse(filepath); err != nil {
			return nil, err
		} else {
			path = p
		}
	}
	if params != nil {
		path.RawQuery = fmt.Sprintf("token=%s&type=%s&redirect_to=%s", url.QueryEscape(params.Token), url.QueryEscape(params.Type), encodeRedirectURL(params.RedirectTo))
	}
	return path, nil
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
