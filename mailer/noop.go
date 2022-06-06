package mailer

import (
	"errors"

	"github.com/netlify/gotrue/models"
)

type noopMailer struct {
	Mailer MailClient
}

func (m noopMailer) ValidateEmail(email string) error {
	return nil
}

func (m *noopMailer) InviteMail(user *models.User, referrerURL string) error {
	return nil
}

func (m *noopMailer) ConfirmationMail(user *models.User, referrerURL string) error {
	return nil
}

func (m noopMailer) RecoveryMail(user *models.User, referrerURL string) error {
	return nil
}

func (m noopMailer) MagicLinkMail(user *models.User, referrerURL string) error {
	return nil
}

func (m *noopMailer) EmailChangeMail(user *models.User, referrerURL string) error {
	return nil
}

func (m noopMailer) Send(user *models.User, subject, body string, data map[string]interface{}) error {
	return nil
}

func (m noopMailer) GetEmailActionLink(user *models.User, actionType, referrerURL string) (string, error) {
	return "", nil
}

type noopMailClient struct{}

func (m *noopMailClient) Mail(to, subjectTemplate, templateURL, defaultTemplate string, templateData map[string]interface{}) error {
	if to == "" {
		return errors.New("to field cannot be empty")
	}
	return nil
}
