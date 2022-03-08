package mailer

import (
	"net/url"
	"regexp"

	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/mailme"
	"github.com/sirupsen/logrus"
	"gopkg.in/gomail.v2"
)

// Mailer defines the interface a mailer must implement.
type Mailer interface {
	Send(user *models.User, subject, body string, data map[string]interface{}) error
	InviteMail(user *models.User, referrerURL string) error
	ConfirmationMail(user *models.User, referrerURL string) error
	RecoveryMail(user *models.User, referrerURL string) error
	MagicLinkMail(user *models.User, referrerURL string) error
	EmailChangeMail(user *models.User, referrerURL string) error
	ValidateEmail(email string) error
	GetEmailActionLink(user *models.User, actionType, referrerURL string) (string, error)
}

// NewMailer returns a new gotrue mailer
func NewMailer(instanceConfig *conf.Configuration) Mailer {
	mail := gomail.NewMessage()
	from := mail.FormatAddress(instanceConfig.SMTP.AdminEmail, instanceConfig.SMTP.SenderName)

	var mailClient MailClient
	if instanceConfig.SMTP.Host == "" {
		logrus.Infof("Noop mail client being used for %v", instanceConfig.SiteURL)
		mailClient = &noopMailClient{}
	} else {
		mailClient = &mailme.Mailer{
			Host:    instanceConfig.SMTP.Host,
			Port:    instanceConfig.SMTP.Port,
			User:    instanceConfig.SMTP.User,
			Pass:    instanceConfig.SMTP.Pass,
			From:    from,
			BaseURL: instanceConfig.SiteURL,
			Logger:  logrus.New(),
		}
	}

	return &TemplateMailer{
		SiteURL: instanceConfig.SiteURL,
		Config:  instanceConfig,
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

var urlRegexp = regexp.MustCompile(`^https?://[^/]+`)

func enforceRelativeURL(url string) string {
	return urlRegexp.ReplaceAllString(url, "")
}
