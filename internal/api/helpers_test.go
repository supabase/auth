package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsValidCodeChallenge(t *testing.T) {
	cases := []struct {
		challenge     string
		isValid       bool
		expectedError error
	}{
		{
			challenge:     "invalid",
			isValid:       false,
			expectedError: badRequestError("code challenge has to be between %v and %v characters", MinCodeChallengeLength, MaxCodeChallengeLength),
		},
		{
			challenge:     "codechallengecontainsinvalidcharacterslike@$^&*",
			isValid:       false,
			expectedError: badRequestError("code challenge can only contain alphanumeric characters, hyphens, periods, underscores and tildes"),
		},
		{
			challenge:     "validchallengevalidchallengevalidchallengevalidchallenge",
			isValid:       true,
			expectedError: nil,
		},
	}

	for _, c := range cases {
		valid, err := isValidCodeChallenge(c.challenge)
		require.Equal(t, c.isValid, valid)
		require.Equal(t, c.expectedError, err)
	}
}
