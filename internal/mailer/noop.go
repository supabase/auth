package mailer

import (
	"context"
	"errors"
)

type noopMailClient struct {
	EmailValidator *EmailValidator
}

func (m *noopMailClient) Mail(
	ctx context.Context,
	to, subjectTemplate, templateURL, defaultTemplate string,
	templateData map[string]interface{},
	headers map[string][]string,
	typ string,
) error {
	if to == "" {
		return errors.New("to field cannot be empty")
	}
	if m.EmailValidator != nil {
		if err := m.EmailValidator.Validate(ctx, to); err != nil {
			return err
		}
	}
	return nil
}
