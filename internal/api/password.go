package api

import (
	"context"
	"fmt"
	"strings"
)

// WeakPasswordError encodes an error that a password does not meet strength
// requirements. It is handled specially in errors.go as it gets transformed to
// a HTTPError with a special weak_password field that encodes the Reasons
// slice.
type WeakPasswordError struct {
	Message string
	Reasons []string
}

func (e *WeakPasswordError) Error() string {
	return e.Message
}

func (a *API) checkPasswordStrength(ctx context.Context, password string) error {
	config := a.config

	var messages, reasons []string

	if len(password) < config.Password.MinLength {
		reasons = append(reasons, "length")
		messages = append(messages, fmt.Sprintf("Password should be at least %d characters.", config.Password.MinLength))
	}

	for _, characterSet := range config.Password.RequiredCharacters {
		if characterSet != "" && !strings.ContainsAny(password, characterSet) {
			reasons = append(reasons, "characters")

			messages = append(messages, fmt.Sprintf("Password should contain at least one character of each: %s.", strings.Join(config.Password.RequiredCharacters, ", ")))

			break
		}
	}

	if len(reasons) > 0 {
		return &WeakPasswordError{
			Message: strings.Join(messages, " "),
			Reasons: reasons,
		}
	}

	return nil
}
