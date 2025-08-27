package mailer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apitask"
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
	mc := NewMailClient(globalConfig)
	return NewMailerWithClient(globalConfig, mc)
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
	return &TemplateMailer{
		SiteURL: globalConfig.SiteURL,
		Config:  globalConfig,
		Mailer:  mailClient,
	}
}

// NewMailClient returns a new MailClient based on the given configuration.
func NewMailClient(globalConfig *conf.GlobalConfiguration) MailClient {
	mc := newMailClient(globalConfig)

	// Check if email validation is enabled
	ev := newEmailValidator(globalConfig.Mailer)
	if ev.isEnabled() {
		mc = &emailValidatorMailClient{ev: ev, mc: mc}
	}

	// Check if background emails are enabled
	if globalConfig.Mailer.EmailBackgroundSending {
		mc = &backgroundMailClient{
			mc: mc,
		}
	}
	return mc
}

// newMailClient returns a new MailClient based on the given configuration.
func newMailClient(globalConfig *conf.GlobalConfiguration) MailClient {
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

// Task holds a mail pending delivery by the Handler.
type Task struct {
	mc MailClient

	To              string              `json:"to"`
	SubjectTemplate string              `json:"subject_template"`
	TemplateURL     string              `json:"template_url"`
	DefaultTemplate string              `json:"default_template"`
	TemplateData    map[string]any      `json:"template_data"`
	Headers         map[string][]string `json:"headers"`
	Typ             string              `json:"typ"`
}

// Run implements the Type method of the apitask.Task interface by returning
// the "mailer." prefix followed by the mail type.
func (o *Task) Type() string { return fmt.Sprintf("mailer.%v", o.Typ) }

// Run implements the Run method of the apitask.Task interface by attempting
// to send the mail using the underying mail client.
func (o *Task) Run(ctx context.Context) error {
	return o.mc.Mail(
		ctx,
		o.To,
		o.SubjectTemplate,
		o.TemplateURL,
		o.DefaultTemplate,
		o.TemplateData,
		o.Headers,
		o.Typ)
}

type backgroundMailClient struct {
	mc MailClient
}

// Mail implements mailer.MailClient interface by sending the call to the
// wrapped mail client to the background.
func (o *backgroundMailClient) Mail(
	ctx context.Context,
	to string,
	subjectTemplate string,
	templateURL string,
	defaultTemplate string,
	templateData map[string]any,
	headers map[string][]string,
	typ string,
) error {
	tk := &Task{
		mc:              o.mc,
		To:              to,
		SubjectTemplate: subjectTemplate,
		TemplateURL:     templateURL,
		DefaultTemplate: defaultTemplate,
		TemplateData:    templateData,
		Headers:         headers,
		Typ:             typ,
	}
	return apitask.Run(ctx, tk)
}
