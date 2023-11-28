package api

import "context"

func (a *API) checkPasswordStrength(ctx context.Context, password string) error {
	config := a.config

	if len(password) < config.PasswordMinLength {
		return invalidPasswordLengthError(config.PasswordMinLength)
	}

	return nil
}
