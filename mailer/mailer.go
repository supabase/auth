package mailer

import (
	"net/url"

	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/mailme"
	"github.com/sirupsen/logrus"
	"gopkg.in/gomail.v2"
)

// Mailer defines the interface a mailer must implement.
type Mailer interface {
	Send(user *models.User, subject, body string, data map[string]interface{}) error
	InviteMail(user *models.User, otp, referrerURL string) error
	ConfirmationMail(user *models.User, otp, referrerURL string) error
	RecoveryMail(user *models.User, otp, referrerURL string) error
	MagicLinkMail(user *models.User, otp, referrerURL string) error
	EmailChangeMail(user *models.User, otpNew, otpCurrent, referrerURL string) error
	ReauthenticateMail(user *models.User, otp string) error
	ValidateEmail(email string) error
	GetEmailActionLink(user *models.User, actionType, referrerURL string) (string, error)
}

// NewMailer returns a new gotrue mailer
func NewMailer(tenantConfig *conf.TenantConfiguration) Mailer {
	mail := gomail.NewMessage()
	from := mail.FormatAddress(tenantConfig.SMTP.AdminEmail, tenantConfig.SMTP.SenderName)

	var mailClient MailClient
	if tenantConfig.SMTP.Host == "" {
		logrus.Infof("Noop mail client being used for %v", tenantConfig.SiteURL)
		mailClient = &noopMailClient{}
	} else {
		mailClient = &mailme.Mailer{
			Host:    tenantConfig.SMTP.Host,
			Port:    tenantConfig.SMTP.Port,
			User:    tenantConfig.SMTP.User,
			Pass:    tenantConfig.SMTP.Pass,
			From:    from,
			BaseURL: tenantConfig.SiteURL,
			Logger:  logrus.StandardLogger(),
		}
	}

	return &TemplateMailer{
		SiteURL: tenantConfig.SiteURL,
		Config:  tenantConfig,
		Mailer:  mailClient,
	}
}

func withDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func getSiteURL(referrerURL, siteURL, filepath, fragment string) (string, error) {
	baseURL := siteURL
	if filepath == "" && referrerURL != "" {
		baseURL = referrerURL
	}

	site, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if filepath != "" {
		path, err := url.Parse(filepath)
		if err != nil {
			return "", err
		}
		site = site.ResolveReference(path)
	}
	site.RawQuery = fragment
	return site.String(), nil
}
