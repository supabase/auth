package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
)

func TestPasswordStrengthChecks(t *testing.T) {
	examples := []struct {
		MinLength          int
		RequiredCharacters []string

		Password  string
		Reasons   []string
		ErrorCode apierrors.ErrorCode
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
		{
			// 3 runes but 9 bytes: must still be too short
			MinLength: 6,
			Password:  "密码短",
			Reasons:   []string{"length"},
		},
		{
			MinLength: 6,
			Password:  "密码密码密码",
			Reasons:   nil,
		},
		{
			MinLength:          6,
			RequiredCharacters: []string{},
			Password:           "zZgXb5gzyCNrV36qwbOSbKVQsVJd28mC1TwRpeB0y6sFNICJyjD6bILKJMsjyKDzBdaY5tmi8zY9BWJYmt3vULLmyafjIDLYjy8qhETu0mS2jj1uQBgSAzJn9Zjm8EFa",
			Reasons:            nil,
			ErrorCode:          apierrors.ErrorCodeValidationFailed,
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

		switch {
		case len(example.Reasons) > 0:
			var e *WeakPasswordError
			require.ErrorAs(t, err, &e, "Example %d should fail password strength checks", i)
			require.Equal(t, example.Reasons, e.Reasons, "Example %d failed with wrong reasons", i)
		case example.ErrorCode != "":
			var e *HTTPError
			require.ErrorAs(t, err, &e, "Example %d should fail validation", i)
			require.Equal(t, example.ErrorCode, e.ErrorCode, "Example %d failed with wrong error code", i)
		default:
			require.NoError(t, err, "Example %d failed with error", i)
		}
	}
}
