// Package mailmeclient provides an implementation of mailer.Client that uses
// gopkg.in/gomail.v2 to send via SMTP.
package mailmeclient

import (
	"context"
	"fmt"
	"net/url"

	"gopkg.in/gomail.v2"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
)

// Client lets MailMe send templated mails
type Client struct {
	From      string
	Host      string
	Port      int
	User      string
	Pass      string
	LocalName string

	Logger      logrus.FieldLogger
	MailLogging bool
}

// New returns a new *Mailer based on the given configuration.
func New(globalConfig *conf.GlobalConfiguration) *Client {
	from := globalConfig.SMTP.FromAddress()
	u, _ := url.ParseRequestURI(globalConfig.API.ExternalURL)
	return &Client{
		Host:        globalConfig.SMTP.Host,
		Port:        globalConfig.SMTP.Port,
		User:        globalConfig.SMTP.User,
		Pass:        globalConfig.SMTP.Pass,
		LocalName:   u.Hostname(),
		From:        from,
		Logger:      logrus.StandardLogger(),
		MailLogging: globalConfig.SMTP.LoggingEnabled,
	}
}

// Mail sends a templated mail. It will try to load the template from a URL, and
// otherwise fall back to the default
func (m *Client) Mail(
	ctx context.Context,
	to string,
	subject string,
	body string,
	headers map[string][]string,
	typ string,
) error {
	mail := gomail.NewMessage()
	mail.SetHeader("From", m.From)
	mail.SetHeader("To", to)
	mail.SetHeader("Subject", subject)

	for k, v := range headers {
		if v != nil {
			mail.SetHeader(k, v...)
		}
	}

	mail.SetBody("text/html", body)

	dial := gomail.NewDialer(m.Host, m.Port, m.User, m.Pass)
	if m.LocalName != "" {
		dial.LocalName = m.LocalName
	}

	// structured fields for logging
	fields := logrus.Fields{
		"event":     "mail.send",
		"mail_type": typ,
		"mail_from": m.From,
		"mail_to":   to,
		"smtp_host": m.Host,
		"smtp_port": m.Port,
	}

	// attempt send
	if err := dial.DialAndSend(mail); err != nil {
		// log failure with error and return wrapped error for context
		if m.Logger != nil {
			m.Logger.WithFields(fields).WithError(err).Error("mail.send.failed")
		} else {
			logrus.WithFields(fields).WithError(err).Error("mail.send.failed")
		}
		return fmt.Errorf("mailmeclient: send failed: %w", err)
	}

	// success
	if m.MailLogging {
		if m.Logger != nil {
			m.Logger.WithFields(fields).Info("mail.send.success")
		} else {
			logrus.WithFields(fields).Info("mail.send.success")
		}
	}
	return nil
}
