package mailer

import (
	"errors"
)

type noopMailClient struct{}

func (m *noopMailClient) Mail(to, subjectTemplate, templateURL, defaultTemplate string, templateData map[string]interface{}, headers map[string][]string, typ string) error {
	if to == "" {
		return errors.New("to field cannot be empty")
	}
	return nil
}
