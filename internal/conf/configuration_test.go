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

func TestValidateAndPopulateExtensibilityPoint(t *testing.T) {
	cases := []struct {
		desc           string
		uri            string
		expectedResult string
	}{
		// Positive test cases
		{desc: "Valid URI", uri: "pg-functions://postgres/auth/verification_hook_reject", expectedResult: `"auth"."verification_hook_reject"`},
		{desc: "Another Valid URI", uri: "pg-functions://postgres/user_management/add_user", expectedResult: `"user_management"."add_user"`},
		{desc: "Another Valid URI", uri: "pg-functions://postgres/MySpeCial/FUNCTION_THAT_YELLS_AT_YOU", expectedResult: `"MySpeCial"."FUNCTION_THAT_YELLS_AT_YOU"`},

		// Negative test cases
		{desc: "Invalid Schema Name", uri: "pg-functions://postgres/123auth/verification_hook_reject", expectedResult: ""},
		{desc: "Invalid Function Name", uri: "pg-functions://postgres/auth/123verification_hook_reject", expectedResult: ""},
		{desc: "Insufficient Path Parts", uri: "pg-functions://postgres/auth", expectedResult: ""},
	}

	for _, tc := range cases {
		ep := ExtensibilityPointConfiguration{URI: tc.uri}
		err := ep.ValidateAndPopulateExtensibilityPoint()
		if tc.expectedResult != "" {
			require.NoError(t, err)
			require.Equal(t, tc.expectedResult, ep.HookName)
		} else {
			require.Error(t, err)
			require.Empty(t, ep.HookName)
		}
	}
}
