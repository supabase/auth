package hooks

import (
	"github.com/stretchr/testify/suite"
	"github.com/supabase/gotrue/internal/conf"
	"testing"
)

type HookTestSuite struct {
	suite.Suite
}

func TestHooks(t *testing.T) {
	ts := &HookTestSuite{}
	suite.Run(t, ts)
}

func TestFetchHookName(ts *testing.T) {
	cases := []struct {
		desc           string
		uri            string
		expectedResult string
		expectedError  string // Using string to represent the error for simplicity
	}{
		// Positive test cases
		{desc: "Valid URI", uri: "pg-functions://postgres/auth/verification_hook_reject", expectedResult: "auth.verification_hook_reject", expectedError: ""},
		{desc: "Another Valid URI", uri: "pg-functions://postgres/user_management/add_user", expectedResult: "user_management.add_user", expectedError: ""},

		// Negative test cases
		{desc: "Invalid Schema Name", uri: "pg-functions://postgres/123auth/verification_hook_reject", expectedResult: "", expectedError: "invalid schema name: 123auth"},
		{desc: "Invalid Function Name", uri: "pg-functions://postgres/auth/123verification_hook_reject", expectedResult: "", expectedError: "invalid table name: 123verification_hook_reject"},
		{desc: "Insufficient Path Parts", uri: "pg-functions://postgres/auth", expectedResult: "", expectedError: "URI path does not contain enough parts"},
		// {desc: "Incorrect URI Format", uri: "http://postgres/auth/verification_hook_reject", expectedResult: "", expectedError: "invalid URI format"},
	}

	for _, tc := range cases {
		ts.Run(tc.desc, func(t *testing.T) {
			ep := conf.ExtensibilityPointConfiguration{URI: tc.uri}
			result, err := FetchHookName(ep)
			if err != nil && err.Error() != tc.expectedError {
				t.Errorf("Test %s failed: expected error %v, got %v", tc.desc, tc.expectedError, err)
			}
			if result != tc.expectedResult {
				t.Errorf("Test %s failed: expected result %v, got %v", tc.desc, tc.expectedResult, result)
			}
		})
	}
}
