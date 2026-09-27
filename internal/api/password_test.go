package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
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
		{
			MinLength:          6,
			RequiredCharacters: []string{},
			Password:           "zZgXb5gzyCNrV36qwbOSbKVQsVJd28mC1TwRpeB0y6sFNICJyjD6bILKJMsjyKDzBdaY5tmi8zY9BWJYmt3vULLmyafjIDLYjy8qhETu0mS2jj1uQBgSAzJn9Zjm8EFa",
			Reasons:            nil,
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

		switch e := err.(type) {
		case *WeakPasswordError:
			require.Equal(t, e.Reasons, example.Reasons, "Example %d failed with wrong reasons", i)
		case *HTTPError:
			require.Equal(t, e.ErrorCode, apierrors.ErrorCodeValidationFailed, "Example %d failed with wrong error code", i)
		default:
			require.NoError(t, err, "Example %d failed with error", i)
		}
	}
}

func TestPasswordStrengthMaximumLengthBytes(t *testing.T) {
	api := &API{config: &conf.GlobalConfiguration{
		Password: conf.PasswordConfiguration{MinLength: 6},
	}}

	for _, tc := range []struct {
		name     string
		password string
		tooLong  bool
	}{
		{"ASCII at limit", strings.Repeat("a", 72), false},
		{"ASCII over limit", strings.Repeat("a", 73), true},
		{"Korean at limit", strings.Repeat("가", 24), false},
		{"Korean over limit", strings.Repeat("가", 25), true},
		{"emoji at limit", strings.Repeat("😀", 18), false},
		{"emoji over limit", strings.Repeat("😀", 19), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := api.checkPasswordStrength(context.Background(), tc.password)
			if !tc.tooLong {
				require.NoError(t, err)
				return
			}

			var httpErr *HTTPError
			require.ErrorAs(t, err, &httpErr)
			require.Equal(t, http.StatusBadRequest, httpErr.HTTPStatus)
			require.Equal(t, apierrors.ErrorCodeValidationFailed, httpErr.ErrorCode)
			require.Equal(t, "Password cannot be longer than 72 bytes", httpErr.Message)
		})
	}
}
