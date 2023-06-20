package api

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func removeLocalhostFromPrivateIPBlock() *net.IPNet {
	_, localhost, _ := net.ParseCIDR("127.0.0.0/8")

	var localhostIndex int
	for i := 0; i < len(privateIPBlocks); i++ {
		if privateIPBlocks[i] == localhost {
			localhostIndex = i
		}
	}
	privateIPBlocks = append(privateIPBlocks[:localhostIndex], privateIPBlocks[localhostIndex+1:]...)

	return localhost
}

func unshiftPrivateIPBlock(address *net.IPNet) {
	privateIPBlocks = append([]*net.IPNet{address}, privateIPBlocks...)
}

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
