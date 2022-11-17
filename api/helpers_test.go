package api

import (
	"net"
	"testing"

	"github.com/netlify/gotrue/conf"
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

func TestCheckPasswordMeetsRequirements(t *testing.T) {
	tests := []struct {
		name     string
		config   conf.GlobalConfiguration
		password string
		expected *HTTPError
	}{
		{
			"Password is too short",
			conf.GlobalConfiguration{PasswordMinLength: 3},
			"hi",
			unprocessableEntityError("Password should be at least 3 characters"),
		},
		{
			"Password is right length",
			conf.GlobalConfiguration{PasswordMinLength: 3},
			"hello",
			nil,
		},
		{
			"Password missing uppercase",
			conf.GlobalConfiguration{
				PasswordComplexity: conf.PasswordComplexityConfiguration{
					RequireUppercase: true,
				}},
			"hello",
			unprocessableEntityError("Password must contain at least one character from the set: ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		},
		{
			"Password missing lowercase",
			conf.GlobalConfiguration{
				PasswordComplexity: conf.PasswordComplexityConfiguration{
					RequireLowercase: true,
				}},
			"HELLO",
			unprocessableEntityError("Password must contain at least one character from the set: abcdefghijklmnopqrstuvwxyz"),
		},
		{
			"Password missing numbers",
			conf.GlobalConfiguration{
				PasswordComplexity: conf.PasswordComplexityConfiguration{
					RequireNumber: true,
				}},
			"hello",
			unprocessableEntityError("Password must contain at least one character from the set: 0123456789"),
		},
		{
			"Password missing special",
			conf.GlobalConfiguration{
				PasswordComplexity: conf.PasswordComplexityConfiguration{
					RequireSpecial: true,
				}},
			"hello",
			unprocessableEntityError("Password must contain at least one character from the set: !@#$%%^&*()_+-=[]{}|'"),
		},
		{
			"Password missing all categories",
			conf.GlobalConfiguration{
				PasswordComplexity: conf.PasswordComplexityConfiguration{
					RequireLowercase: true,
					RequireUppercase: true,
					RequireNumber:    true,
					RequireSpecial:   true,
				}},
			"",
			unprocessableEntityError("Password must contain at least one character from the set: abcdefghijklmnopqrstuvwxyz"),
		},
		{
			"Password missing some categories",
			conf.GlobalConfiguration{
				PasswordComplexity: conf.PasswordComplexityConfiguration{
					RequireLowercase: true,
					RequireUppercase: true,
					RequireNumber:    true,
					RequireSpecial:   true,
				}},
			"abcABC",
			unprocessableEntityError("Password must contain at least one character from the set: 0123456789"),
		},
		{
			"Password meeting all requirements",
			conf.GlobalConfiguration{
				PasswordComplexity: conf.PasswordComplexityConfiguration{
					RequireLowercase: true,
					RequireUppercase: true,
					RequireNumber:    true,
					RequireSpecial:   true,
				}},
			"abcABC123!",
			nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := checkPasswordMeetsRequirements(&test.config, test.password)
			require.Equal(t, test.expected, actual)
		})
	}
}
