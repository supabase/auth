package api

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestPasswordStrengthChecks(t *testing.T) {
	examples := []struct {
		MinLength          int
		RequiredCharacters []string

		Password string
		Reasons  []string
	}{
		{
			MinLength: 6,
			Password:  "12345",
			Reasons: []string{
				"length",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "123",
			Reasons: []string{
				"length",
				"characters",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "a123",
			Reasons: []string{
				"length",
				"characters",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "ab123",
			Reasons: []string{
				"length",
				"characters",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "c123",
			Reasons: []string{
				"length",
				"characters",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "abc123",
			Reasons:  nil,
		},
	}

	for i, example := range examples {
		api := &API{
			config: &conf.GlobalConfiguration{
				Password: conf.PasswordConfiguration{
					MinLength:          example.MinLength,
					RequiredCharacters: conf.PasswordRequiredCharacters(example.RequiredCharacters),
				},
			},
		}

		err := api.checkPasswordStrength(context.Background(), example.Password)
		if example.Reasons == nil {
			require.NoError(t, err, "Example %d failed with error", i)
		} else {
			require.Equal(t, err.(*WeakPasswordError).Reasons, example.Reasons, "Example %d failed with wrong reasons", i)
		}
	}
}

func TestCheckPasswordLength(t *testing.T) {
    examples := []struct {
        Password string
        Error    error
    }{
        {
            Password: strings.Repeat("a", MaxPasswordLength - 1),
            Error:    nil,
        },
        {
            Password: strings.Repeat("a", MaxPasswordLength),
            Error:    nil,
        },
        {
            Password: strings.Repeat("a", MaxPasswordLength + 1),
            Error:    unprocessableEntityError(fmt.Sprintf("Password cannot be longer than %d characters", MaxPasswordLength)),
        },
    }

    for i, example := range examples {
        api := &API{}

        err := api.checkPasswordLength(example.Password)
        if example.Error == nil {
            require.NoError(t, err, "Example %d failed with error", i)
        } else {
            require.Equal(t, example.Error, err, "Example %d failed with wrong error", i)
        }
    }
}