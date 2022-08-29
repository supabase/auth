package mailer

import (
	"errors"
)

type noopMailClient struct{}

func (m *noopMailClient) Mail(to, subjectTemplate, templateURL, defaultTemplate string, templateData map[string]interface{}) error {
	if to == "" {
		return errors.New("to field cannot be empty")
	}
	return nil
}
