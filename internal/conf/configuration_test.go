package conf

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	defer os.Clearenv()
	os.Exit(m.Run())
}

func TestGlobal(t *testing.T) {
	os.Setenv("GOTRUE_SITE_URL", "http://localhost:8080")
	os.Setenv("GOTRUE_DB_DRIVER", "postgres")
	os.Setenv("GOTRUE_DB_DATABASE_URL", "fake")
	os.Setenv("GOTRUE_OPERATOR_TOKEN", "token")
	os.Setenv("GOTRUE_API_REQUEST_ID_HEADER", "X-Request-ID")
	os.Setenv("GOTRUE_JWT_SECRET", "secret")
	os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	os.Setenv("GOTRUE_HOOK_MFA_VERIFICATION_ATTEMPT_URI", "pg-functions://postgres/auth/count_failed_attempts")
	gc, err := LoadGlobal("")
	require.NoError(t, err)
	require.NotNil(t, gc)
	assert.Equal(t, "X-Request-ID", gc.API.RequestIDHeader)
	assert.Equal(t, "pg-functions://postgres/auth/count_failed_attempts", gc.Hook.MFAVerificationAttempt.URI)
}

func TestPasswordRequiredCharactersDecode(t *testing.T) {
	examples := []struct {
		Value  string
		Result []string
	}{
		{
			Value: "a:b:c",
			Result: []string{
				"a",
				"b",
				"c",
			},
		},
		{
			Value: "a\\:b:c",
			Result: []string{
				"a:b",
				"c",
			},
		},
		{
			Value: "a:b\\:c",
			Result: []string{
				"a",
				"b:c",
			},
		},
		{
			Value: "\\:a:b:c",
			Result: []string{
				":a",
				"b",
				"c",
			},
		},
		{
			Value: "a:b:c\\:",
			Result: []string{
				"a",
				"b",
				"c:",
			},
		},
		{
			Value: "::\\::",
			Result: []string{
				":",
			},
		},
		{
			Value:  "",
			Result: nil,
		},
		{
			Value: " ",
			Result: []string{
				" ",
			},
		},
	}

	for i, example := range examples {
		var into PasswordRequiredCharacters
		require.NoError(t, into.Decode(example.Value), "Example %d failed with error", i)

		require.Equal(t, []string(into), example.Result, "Example %d got unexpected result", i)
	}
}

func TestValidateExtensibilityPoint(t *testing.T) {
	cases := []struct {
		desc        string
		uri         string
		expectError bool
	}{
		// Positive test cases
		{desc: "Valid URI", uri: "pg-functions://postgres/auth/verification_hook_reject", expectError: false},
		{desc: "Another Valid URI", uri: "pg-functions://postgres/user_management/add_user", expectError: false},
		{desc: "Another Valid URI", uri: "pg-functions://postgres/MySpeCial/FUNCTION_THAT_YELLS_AT_YOU", expectError: false},

		// Negative test cases
		{desc: "Invalid Schema Name", uri: "pg-functions://postgres/123auth/verification_hook_reject", expectError: true},
		{desc: "Invalid Function Name", uri: "pg-functions://postgres/auth/123verification_hook_reject", expectError: true},
		{desc: "Insufficient Path Parts", uri: "pg-functions://postgres/auth", expectError: true},
	}

	for _, tc := range cases {
		ep := ExtensibilityPointConfiguration{URI: tc.uri}
		err := ep.ValidateExtensibilityPoint()
		if tc.expectError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}
