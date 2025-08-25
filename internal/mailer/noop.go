package mailer

import (
	"context"
	"errors"
	"time"
)

type noopMailClient struct {
	EmailValidator *EmailValidator
	Delay          time.Duration
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

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if m.EmailValidator != nil {
		if err := m.EmailValidator.Validate(ctx, to); err != nil {
			return err
		}
	}
	return nil
}
