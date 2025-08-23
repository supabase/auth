package mailer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
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

type EmailParams struct {
	Token      string
	Type       string
	RedirectTo string
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

// NewMailer returns a new gotrue mailer
func NewMailer(globalConfig *conf.GlobalConfiguration) Mailer {
	from := globalConfig.SMTP.FromAddress()
	u, _ := url.ParseRequestURI(globalConfig.API.ExternalURL)

	var mailClient MailClient
	if globalConfig.SMTP.Host == "" {
		logrus.Infof("Noop mail client being used for %v", globalConfig.SiteURL)
		mailClient = &noopMailClient{
			EmailValidator: newEmailValidator(globalConfig.Mailer),
		}
	} else {
		mailClient = &MailmeMailer{
			Host:        globalConfig.SMTP.Host,
			Port:        globalConfig.SMTP.Port,
			User:        globalConfig.SMTP.User,
			Pass:        globalConfig.SMTP.Pass,
			LocalName:   u.Hostname(),
			From:        from,
			BaseURL:     globalConfig.SiteURL,
			Logger:      logrus.StandardLogger(),
			MailLogging: globalConfig.SMTP.LoggingEnabled,
		}
	}

	return &TemplateMailer{
		SiteURL: globalConfig.SiteURL,
		Config:  globalConfig,
		Mailer:  mailClient,
	}
}

type emailValidatorMailClient struct {
	ev *EmailValidator
	mc MailClient
}

// Mail implements mailer.MailClient interface by calling validate before
// passing the mail request to the next MailClient.
func (o *emailValidatorMailClient) Mail(
	ctx context.Context,
	to string,
	subjectTemplate string,
	templateURL string,
	defaultTemplate string,
	templateData map[string]any,
	headers map[string][]string,
	typ string,
) error {
	if err := o.ev.Validate(ctx, to); err != nil {
		return err
	}
	return o.mc.Mail(
		ctx,
		to,
		subjectTemplate,
		templateURL,
		defaultTemplate,
		templateData,
		headers,
		typ,
	)
}

// NewMailerWithClient returns a new Mailer that will use the given MailClient.
func NewMailerWithClient(
	globalConfig *conf.GlobalConfiguration,
	mailClient MailClient,
) Mailer {
	ev := newEmailValidator(globalConfig.Mailer)
	mr := &emailValidatorMailClient{ev: ev, mc: mailClient}
	return &TemplateMailer{
		SiteURL: globalConfig.SiteURL,
		Config:  globalConfig,
		Mailer:  mr,
	}
}

// NewMailClient returns a new MailClient based on the given configuration.
func NewMailClient(globalConfig *conf.GlobalConfiguration) MailClient {
	if globalConfig.SMTP.Host == "" {
		logrus.Infof("Noop mail client being used for %v", globalConfig.SiteURL)
		return &noopMailClient{
			EmailValidator: newEmailValidator(globalConfig.Mailer),
		}
	}

	from := globalConfig.SMTP.FromAddress()
	u, _ := url.ParseRequestURI(globalConfig.API.ExternalURL)
	return &MailmeMailer{
		Host:        globalConfig.SMTP.Host,
		Port:        globalConfig.SMTP.Port,
		User:        globalConfig.SMTP.User,
		Pass:        globalConfig.SMTP.Pass,
		LocalName:   u.Hostname(),
		From:        from,
		BaseURL:     globalConfig.SiteURL,
		Logger:      logrus.StandardLogger(),
		MailLogging: globalConfig.SMTP.LoggingEnabled,
		// EmailValidator: newEmailValidator(globalConfig.Mailer),
	}
}

func withDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func getPath(filepath string, params *EmailParams) (*url.URL, error) {
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
