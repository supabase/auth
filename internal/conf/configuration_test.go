package conf

import (
	"encoding/base64"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
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
	os.Setenv("GOTRUE_HOOK_SEND_SMS_SECRETS", "v1,whsec_aWxpa2VzdXBhYmFzZXZlcnltdWNoYW5kaWhvcGV5b3Vkb3Rvbw==")
	os.Setenv("GOTRUE_SMTP_HEADERS", `{"X-PM-Metadata-project-ref":["project_ref"],"X-SES-Message-Tags":["ses:feedback-id-a=project_ref,ses:feedback-id-b=$messageType"]}`)
	os.Setenv("GOTRUE_MAILER_EMAIL_VALIDATION_SERVICE_HEADERS", `{"apikey":["test"]}`)
	os.Setenv("GOTRUE_SMTP_LOGGING_ENABLED", "true")
	gc, err := LoadGlobal("")
	require.NoError(t, err)
	assert.Equal(t, true, gc.SMTP.LoggingEnabled)
	assert.Equal(t, "project_ref", gc.SMTP.NormalizedHeaders()["X-PM-Metadata-project-ref"][0])
	require.NotNil(t, gc)
	assert.Equal(t, "X-Request-ID", gc.API.RequestIDHeader)
	assert.Equal(t, "pg-functions://postgres/auth/count_failed_attempts", gc.Hook.MFAVerificationAttempt.URI)

	{
		os.Setenv("GOTRUE_RATE_LIMIT_EMAIL_SENT", "0/1h")

		gc, err := LoadGlobal("")
		require.NoError(t, err)
		assert.Equal(t, float64(0), gc.RateLimitEmailSent.Events)
		assert.Equal(t, time.Hour, gc.RateLimitEmailSent.OverTime)
	}

	{
		os.Setenv("GOTRUE_RATE_LIMIT_EMAIL_SENT", "10/1h")

		gc, err := LoadGlobal("")
		require.NoError(t, err)
		assert.Equal(t, float64(10), gc.RateLimitEmailSent.Events)
		assert.Equal(t, time.Hour, gc.RateLimitEmailSent.OverTime)
	}

	{
		hdrs := gc.Mailer.GetEmailValidationServiceHeaders()
		assert.Equal(t, 1, len(hdrs["apikey"]))
		assert.Equal(t, "test", hdrs["apikey"][0])
	}

	{
		cfg, err := LoadGlobalFromEnv()
		require.NoError(t, err)
		require.NotNil(t, cfg)
	}

	{
		cfg, err := LoadGlobal("")
		require.NoError(t, err)
		require.NotNil(t, cfg)
	}

	{
		cfg, err := LoadGlobal("__invalid__")
		require.Error(t, err)
		require.Nil(t, cfg)
	}

	{
		os.Setenv("GOTRUE_MAILER_AUTOCONFIRM", "TRUE")
		os.Setenv("GOTRUE_MAILER_ALLOW_UNVERIFIED_EMAIL_SIGN_INS", "TRUE")
		cfg, err := LoadGlobal("")
		require.Error(t, err)
		require.Nil(t, cfg)
		os.Setenv("GOTRUE_MAILER_AUTOCONFIRM", "FALSE")
		os.Setenv("GOTRUE_MAILER_ALLOW_UNVERIFIED_EMAIL_SIGN_INS", "FALSE")
	}

	{
		os.Setenv("API_EXTERNAL_URL", "")
		cfg := new(GlobalConfiguration)
		err := loadGlobal(cfg)
		require.Error(t, err)
		os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	}

	{
		os.Setenv("API_EXTERNAL_URL", "")
		cfg := new(GlobalConfiguration)
		cfg.Hook = HookConfiguration{
			PasswordVerificationAttempt: ExtensibilityPointConfiguration{
				Enabled: true,
				URI:     "\n",
			},
		}

		err := populateGlobal(cfg)
		require.Error(t, err)
		os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	}

	{
		os.Setenv("API_EXTERNAL_URL", "")
		cfg := new(GlobalConfiguration)
		cfg.Hook = HookConfiguration{
			SendSMS: ExtensibilityPointConfiguration{
				Enabled: true,
				URI:     "\n",
			},
		}

		err := populateGlobal(cfg)
		require.Error(t, err)
		os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	}

	{
		os.Setenv("API_EXTERNAL_URL", "")
		cfg := new(GlobalConfiguration)
		cfg.Hook = HookConfiguration{
			SendEmail: ExtensibilityPointConfiguration{
				Enabled: true,
				URI:     "\n",
			},
		}

		err := populateGlobal(cfg)
		require.Error(t, err)
		os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	}

	{
		os.Setenv("API_EXTERNAL_URL", "")
		cfg := new(GlobalConfiguration)
		cfg.Hook = HookConfiguration{
			MFAVerificationAttempt: ExtensibilityPointConfiguration{
				Enabled: true,
				URI:     "\n",
			},
		}

		err := populateGlobal(cfg)
		require.Error(t, err)
		os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	}

	{
		os.Setenv("API_EXTERNAL_URL", "")
		cfg := new(GlobalConfiguration)
		cfg.Hook = HookConfiguration{
			CustomAccessToken: ExtensibilityPointConfiguration{
				Enabled: true,
				URI:     "\n",
			},
		}

		err := populateGlobal(cfg)
		require.Error(t, err)
		os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	}

	{
		os.Setenv("API_EXTERNAL_URL", "")
		cfg := new(GlobalConfiguration)
		cfg.SAML = SAMLConfiguration{
			Enabled: true,
		}

		err := populateGlobal(cfg)
		require.Error(t, err)
		os.Setenv("API_EXTERNAL_URL", "http://localhost:9999")
	}

	{
		cfg := new(GlobalConfiguration)
		cfg.Sms.Provider = "invalid"

		err := populateGlobal(cfg)
		require.NoError(t, err)
	}

	{
		cfg := new(GlobalConfiguration)
		cfg.Sms.Provider = "invalid"
		cfg.Sms.Template = "{{{{{{{{{}}}}}}}}}"

		err := populateGlobal(cfg)
		require.Error(t, err)
	}

	{
		cfg := new(GlobalConfiguration)
		cfg.MFA.Phone.EnrollEnabled = true
		cfg.MFA.Phone.Template = "{{{{{{{{{}}}}}}}}}"

		err := populateGlobal(cfg)
		require.Error(t, err)
	}

	{
		cfg := new(GlobalConfiguration)
		cfg.MFA.Phone.EnrollEnabled = true

		err := populateGlobal(cfg)
		require.NoError(t, err)
	}
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

func TestHTTPHookSecretsDecode(t *testing.T) {
	examples := []struct {
		Value  string
		Result []string
	}{
		{
			Value:  "v1,whsec_secret1|v1a,whpk_secrets:whsk_secret2|v1,whsec_secret3",
			Result: []string{"v1,whsec_secret1", "v1a,whpk_secrets:whsk_secret2", "v1,whsec_secret3"},
		},
		{
			Value:  "v1,whsec_singlesecret",
			Result: []string{"v1,whsec_singlesecret"},
		},
		{
			Value:  " ",
			Result: []string{" "},
		},
		{
			Value:  "",
			Result: nil,
		},
		{
			Value: "|a|b|c",
			Result: []string{
				"a",
				"b",
				"c",
			},
		},
		{
			Value:  "||||",
			Result: nil,
		},
		{
			Value:  "::",
			Result: []string{"::"},
		},
		{
			Value:  "secret1::secret3",
			Result: []string{"secret1::secret3"},
		},
	}

	for i, example := range examples {
		var into HTTPHookSecrets

		require.NoError(t, into.Decode(example.Value), "Example %d failed with error", i)
		require.Equal(t, []string(into), example.Result, "Example %d got unexpected result", i)
	}
}

func TestValidateExtensibilityPointURI(t *testing.T) {
	cases := []struct {
		desc        string
		uri         string
		expectError bool
	}{
		// Positive test cases
		{desc: "Valid HTTPS URI", uri: "https://asdfgggqqwwerty.website.co/functions/v1/custom-sms-sender", expectError: false},
		{desc: "Valid HTTPS URI", uri: "HTTPS://www.asdfgggqqwwerty.website.co/functions/v1/custom-sms-sender", expectError: false},
		{desc: "Valid Postgres URI", uri: "pg-functions://postgres/auth/verification_hook_reject", expectError: false},
		{desc: "Another Valid URI", uri: "pg-functions://postgres/user_management/add_user", expectError: false},
		{desc: "Another Valid URI", uri: "pg-functions://postgres/MySpeCial/FUNCTION_THAT_YELLS_AT_YOU", expectError: false},
		{desc: "Valid HTTP URI", uri: "http://localhost/functions/v1/custom-sms-sender", expectError: false},

		// Negative test cases
		{desc: "Invalid HTTP URI", uri: "http://asdfgggg.website.co/functions/v1/custom-sms-sender", expectError: true},
		{desc: "Invalid HTTPS URI (HTTP)", uri: "http://asdfgggqqwwerty.supabase.co/functions/v1/custom-sms-sender", expectError: true},
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

func TestValidateExtensibilityPointSecrets(t *testing.T) {
	validHTTPSURI := "https://asdfgggqqwwerty.website.co/functions/v1/custom-sms-sender"
	cases := []struct {
		desc        string
		secret      []string
		expectError bool
	}{
		// Positive test cases
		{desc: "Valid Symmetric Secret", secret: []string{"v1,whsec_NDYzODhlNTY0ZGI1OWZjYTU2NjMwN2FhYzM3YzBkMWQ0NzVjNWRkNTJmZDU0MGNhYTAzMjVjNjQzMzE3Mjk2Zg====="}, expectError: false},
		{desc: "Valid Asymmetric Secret", secret: []string{"v1a,whpk_NDYzODhlNTY0ZGI1OWZjYTU2NjMwN2FhYzM3YzBkMWQ0NzVjNWRkNTJmZDU0MGNhYTAzMjVjNjQzMzE3Mjk2Zg==:whsk_abc889a6b1160015025064f108a48d6aba1c7c95fa8e304b4d225e8ae0121511"}, expectError: false},
		{desc: "Valid Mix of Symmetric and asymmetric Secret", secret: []string{"v1,whsec_2b49264c90fd15db3bb0e05f4e1547b9c183eb06d585be8a", "v1a,whpk_46388e564db59fca566307aac37c0d1d475c5dd52fd540caa0325c643317296f:whsk_YWJjODg5YTZiMTE2MDAxNTAyNTA2NGYxMDhhNDhkNmFiYTFjN2M5NWZhOGUzMDRiNGQyMjVlOGFlMDEyMTUxMSI="}, expectError: false},

		// Negative test cases
		{desc: "Invalid Asymmetric Secret", secret: []string{"v1a,john:jill", "jill"}, expectError: true},
		{desc: "Invalid Symmetric Secret", secret: []string{"tommy"}, expectError: true},
	}
	for _, tc := range cases {
		ep := ExtensibilityPointConfiguration{URI: validHTTPSURI, HTTPHookSecrets: tc.secret}
		err := ep.ValidateExtensibilityPoint()
		if tc.expectError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}

	}

}

func TestTime(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2025-01-01T10:00:00.00Z")

	cases := []struct {
		txt string
		exp time.Time
		err string
	}{

		// valid
		{
			txt: now.Format(time.RFC3339),
			exp: now,
		},

		// trimmed
		{
			txt: "  " + now.Format(time.RFC3339) + "\n  \r",
			exp: now,
		},

		// len < 1
		{
			txt: "",
			exp: time.Time{},
		},

		// invalid time format
		{
			txt: "invalid",
			exp: time.Time{},
			err: `"invalid" as "2006-01-02T15:04:05Z07:00":` +
				` cannot parse "invalid" as "2006"`,
		},
	}

	for idx, tc := range cases {
		t.Logf("test #%v - exp err %v with time %v from UnmarshalText(%q)",
			idx, tc.err, tc.exp, tc.txt)

		var v Time
		err := v.UnmarshalText([]byte(tc.txt))
		if tc.err != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.err)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, tc.exp, v.Time)
	}
}

func TestValidate(t *testing.T) {
	type testCase struct {
		val   interface{ Validate() error }
		check func(t *testing.T, v any)
		err   string
	}
	cases := []testCase{
		{
			val: &APIConfiguration{ExternalURL: "http://localhost"},
		},
		{
			val: &APIConfiguration{ExternalURL: "invalid"},
			err: `parse "invalid": invalid URI for request`,
		},

		{
			val: &APIConfiguration{ExternalURL: "invalid"},
			err: `parse "invalid": invalid URI for request`,
		},

		{
			val: &SessionsConfiguration{Timebox: nil},
		},
		{
			val: &SessionsConfiguration{Timebox: new(time.Duration)},
			err: `conf: session timebox duration must` +
				` be positive when set, was 0`,
		},
		{
			val: &SessionsConfiguration{Timebox: toPtr(time.Duration(-1))},
			err: `conf: session timebox duration must` +
				` be positive when set, was -1`,
		},
		{
			val: &SessionsConfiguration{AllowLowAAL: nil},
		},
		{
			val: &SessionsConfiguration{AllowLowAAL: new(time.Duration)},
			err: `conf: session allow low AAL duration must be positive when set, was 0`,
		},
		{
			val: &SessionsConfiguration{AllowLowAAL: toPtr(time.Duration(-1))},
			err: `conf: session allow low AAL duration must be positive when set, was -1`,
		},
		{
			val: &SessionsConfiguration{Timebox: toPtr(time.Duration(1))},
		},

		{
			val: &SMTPConfiguration{},
		},
		{
			val: &SMTPConfiguration{
				AdminEmail: "test@example.com",
				SenderName: "Test",
			},
			check: func(t *testing.T, v any) {
				got := (v.(*SMTPConfiguration)).FromAddress()
				require.Equal(t, `"Test" <test@example.com>`, got)
			},
		},
		{
			val: &SMTPConfiguration{Headers: "invalid"},
			err: `conf: SMTP headers not a map[string][]string format:` +
				` invalid character 'i' looking for beginning of value`,
		},

		{
			val: &MailerConfiguration{},
		},
		{
			val: &MailerConfiguration{EmailValidationServiceHeaders: "invalid"},
			err: `conf: mailer validation headers not a map[string][]string format:` +
				` invalid character 'i' looking for beginning of value`,
		},

		{
			val: &CaptchaConfiguration{Enabled: false},
		},
		{
			val: &CaptchaConfiguration{Enabled: true},
			err: "unsupported captcha provider:",
		},
		{
			val: &CaptchaConfiguration{
				Enabled:  true,
				Provider: "hcaptcha",
				Secret:   "",
			},
			err: "captcha provider secret is empty",
		},
		{
			val: &CaptchaConfiguration{
				Enabled:  true,
				Provider: "hcaptcha",
				Secret:   "abc",
			},
		},

		{
			val: &DatabaseEncryptionConfiguration{Encrypt: false},
		},
		{
			val: &DatabaseEncryptionConfiguration{
				Encrypt:         true,
				EncryptionKeyID: "",
			},
			err: "conf: encryption key ID must be specified",
		},
		{
			val: &DatabaseEncryptionConfiguration{
				Encrypt:         true,
				EncryptionKeyID: "keyid",
				EncryptionKey:   "|",
			},
			err: "illegal base64 data at input byte 0",
		},
		{
			val: &DatabaseEncryptionConfiguration{
				Encrypt:         true,
				EncryptionKeyID: "keyid",
				EncryptionKey:   "aaaaaaa",
			},
			err: "conf: encryption key is not 256 bits",
		},
		{
			val: &DatabaseEncryptionConfiguration{
				Encrypt:         true,
				EncryptionKeyID: "keyid",
				EncryptionKey: base64.RawURLEncoding.EncodeToString(
					[]byte(strings.Repeat("a", 32)),
				),
			},
			err: "conf: encryption key must also be present in decryption keys",
		},
		{
			val: &DatabaseEncryptionConfiguration{
				Encrypt: true,
				DecryptionKeys: map[string]string{
					"keyid": "|",
				},
				EncryptionKeyID: "keyid",
				EncryptionKey: base64.RawURLEncoding.EncodeToString(
					[]byte(strings.Repeat("a", 32)),
				),
			},
			err: "illegal base64 data at input byte 0",
		},
		{
			val: &DatabaseEncryptionConfiguration{
				Encrypt: true,
				DecryptionKeys: map[string]string{
					"keyid": "aaa",
				},
				EncryptionKeyID: "keyid",
				EncryptionKey: base64.RawURLEncoding.EncodeToString(
					[]byte(strings.Repeat("a", 32)),
				),
			},
			err: `conf: decryption key with ID "keyid" must be 256 bits`,
		},
		{
			val: &DatabaseEncryptionConfiguration{
				Encrypt: true,
				DecryptionKeys: map[string]string{
					"keyid": base64.RawURLEncoding.EncodeToString(
						[]byte(strings.Repeat("a", 32)),
					),
				},
				EncryptionKeyID: "keyid",
				EncryptionKey: base64.RawURLEncoding.EncodeToString(
					[]byte(strings.Repeat("a", 32)),
				),
			},
		},

		{
			val: &SecurityConfiguration{
				Captcha: CaptchaConfiguration{
					Enabled:  true,
					Provider: "hcaptcha",
					Secret:   "abc",
				},
				DBEncryption: DatabaseEncryptionConfiguration{
					Encrypt: true,
					DecryptionKeys: map[string]string{
						"keyid": base64.RawURLEncoding.EncodeToString(
							[]byte(strings.Repeat("a", 32)),
						),
					},
					EncryptionKeyID: "keyid",
					EncryptionKey: base64.RawURLEncoding.EncodeToString(
						[]byte(strings.Repeat("a", 32)),
					),
				},
			},
		},
		{
			val: &SecurityConfiguration{
				Captcha: CaptchaConfiguration{
					Enabled: true,
				},
				DBEncryption: DatabaseEncryptionConfiguration{
					Encrypt: true,
					DecryptionKeys: map[string]string{
						"keyid": base64.RawURLEncoding.EncodeToString(
							[]byte(strings.Repeat("a", 32)),
						),
					},
					EncryptionKeyID: "keyid",
					EncryptionKey: base64.RawURLEncoding.EncodeToString(
						[]byte(strings.Repeat("a", 32)),
					),
				},
			},
			err: `unsupported captcha provider:`,
		},
		{
			val: &SecurityConfiguration{
				Captcha: CaptchaConfiguration{
					Enabled:  true,
					Provider: "hcaptcha",
					Secret:   "abc",
				},
				DBEncryption: DatabaseEncryptionConfiguration{
					Encrypt: true,
				},
			},
			err: `conf: encryption key ID must be specified`,
		},

		{
			val: &TwilioProviderConfiguration{},
			err: `missing Twilio account SID`,
		},
		{
			val: &TwilioProviderConfiguration{
				AccountSid: "a",
			},
			err: `missing Twilio auth token`,
		},
		{
			val: &TwilioProviderConfiguration{
				AccountSid: "a",
				AuthToken:  "b",
			},
			err: `missing Twilio message service SID or Twilio phone number`,
		},
		{
			val: &TwilioProviderConfiguration{
				AccountSid:        "a",
				AuthToken:         "b",
				MessageServiceSid: "c",
			},
		},

		{
			val: &GlobalConfiguration{},
			err: `parse "": empty url`,
		},

		{
			val: &TwilioVerifyProviderConfiguration{},
			err: `missing Twilio account SID`,
		},
		{
			val: &TwilioVerifyProviderConfiguration{
				AccountSid: "a",
			},
			err: `missing Twilio auth token`,
		},
		{
			val: &TwilioVerifyProviderConfiguration{
				AccountSid: "a",
				AuthToken:  "b",
			},
			err: `missing Twilio message service SID or Twilio phone number`,
		},
		{
			val: &TwilioVerifyProviderConfiguration{
				AccountSid:        "a",
				AuthToken:         "b",
				MessageServiceSid: "c",
			},
		},

		{
			val: &MessagebirdProviderConfiguration{},
			err: `missing Messagebird access key`,
		},
		{
			val: &MessagebirdProviderConfiguration{
				AccessKey: "a",
			},
			err: `missing Messagebird originator`,
		},
		{
			val: &MessagebirdProviderConfiguration{
				AccessKey:  "a",
				Originator: "b",
			},
		},

		{
			val: &TextlocalProviderConfiguration{},
			err: `missing Textlocal API key`,
		},
		{
			val: &TextlocalProviderConfiguration{
				ApiKey: "a",
			},
			err: `missing Textlocal sender`,
		},
		{
			val: &TextlocalProviderConfiguration{
				ApiKey: "a",
				Sender: "b",
			},
		},

		{
			val: &VonageProviderConfiguration{},
			err: `missing Vonage API key`,
		},
		{
			val: &VonageProviderConfiguration{
				ApiKey: "a",
			},
			err: `missing Vonage API secret`,
		},
		{
			val: &VonageProviderConfiguration{
				ApiKey:    "a",
				ApiSecret: "b",
			},
			err: `missing Vonage 'from' parameter`,
		},
		{
			val: &VonageProviderConfiguration{
				ApiKey:    "a",
				ApiSecret: "b",
				From:      "c",
			},
		},

		{
			val: &HookConfiguration{
				MFAVerificationAttempt: ExtensibilityPointConfiguration{
					URI: "|",
				},
			},
			err: `only postgres hooks and HTTPS functions are supported at the moment`,
		},
		{
			val: &HookConfiguration{
				MFAVerificationAttempt: ExtensibilityPointConfiguration{
					URI: "http://localhost/foo",
				},
			},
		},
		{
			val: &HookConfiguration{
				MFAVerificationAttempt: ExtensibilityPointConfiguration{
					URI: "\n",
				},
			},
			err: `net/url: invalid control character in URL`,
			check: func(t *testing.T, v any) {
				hcfg := (v.(*HookConfiguration))
				err := hcfg.MFAVerificationAttempt.PopulateExtensibilityPoint()
				require.Error(t, err)
			},
		},
		{
			val: &HookConfiguration{
				MFAVerificationAttempt: ExtensibilityPointConfiguration{
					URI: "http://localhost/foo",
				},
			},
			check: func(t *testing.T, v any) {
				hcfg := (v.(*HookConfiguration))
				err := hcfg.MFAVerificationAttempt.PopulateExtensibilityPoint()
				require.NoError(t, err)
			},
		},
		{
			val: &HookConfiguration{
				MFAVerificationAttempt: ExtensibilityPointConfiguration{
					URI: "pg-functions://foo/bar/baz",
				},
			},
			check: func(t *testing.T, v any) {
				hcfg := (v.(*HookConfiguration))
				err := hcfg.MFAVerificationAttempt.PopulateExtensibilityPoint()
				require.NoError(t, err)
			},
		},
	}

	for idx, tc := range cases {
		t.Logf("test #%v - exp err %v from %T.Validate() (%#[3]v)",
			idx, tc.err, tc.val)

		err := tc.val.Validate()
		if tc.check != nil {
			tc.check(t, tc.val)
		}

		if tc.err != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.err)
			continue
		}
		require.NoError(t, err)
	}
}

func TestMethods(t *testing.T) {
	now, _ := time.Parse(time.RFC3339, "2025-01-01T10:00:00.00Z")

	{
		val := &CORSConfiguration{
			AllowedHeaders: []string{
				"X-Test1",
			},
		}

		got := val.AllAllowedHeaders(nil)
		sort.Strings(got)
		require.Equal(t, []string{"X-Test1"}, got)

		got = val.AllAllowedHeaders([]string{"X-Test2"})
		sort.Strings(got)
		require.Equal(t, []string{"X-Test1", "X-Test2"}, got)

		val.AllowedHeaders = nil
		sort.Strings(got)
		got = val.AllAllowedHeaders([]string{"X-Test2"})
		require.Equal(t, []string{"X-Test2"}, got)

		val.AllowedHeaders = nil
		got = val.AllAllowedHeaders(nil)
		require.Equal(t, ([]string)(nil), got)
	}

	{
		val := &SmsProviderConfiguration{}
		ok := val.IsTwilioVerifyProvider()
		require.False(t, ok)

		val.Provider = "twilio_verify"
		ok = val.IsTwilioVerifyProvider()
		require.True(t, ok)

		// invalid otp (TestOTP map == nil)
		got, ok := val.GetTestOTP("13338888", now)
		require.False(t, ok)
		require.Equal(t, "", got)

		// valid
		val.TestOTP = map[string]string{"13334444": "123456"}
		got, ok = val.GetTestOTP("13334444", now)
		require.True(t, ok)
		require.Equal(t, "123456", got)

		// invalid otp (not in non-nil TestOTP map)
		got, ok = val.GetTestOTP("13338888", now)
		require.False(t, ok)
		require.Equal(t, "", got)

		// valid otp with non-zero time
		val.TestOTPValidUntil = Time{Time: now.Add(time.Second)}
		got, ok = val.GetTestOTP("13334444", now)
		require.True(t, ok)
		require.Equal(t, "123456", got)

		// invalid otp (expired)
		val.TestOTPValidUntil = Time{Time: now.Add(time.Second)}
		got, ok = val.GetTestOTP("13338888", now.Add(time.Second*2))
		require.False(t, ok)
		require.Equal(t, "", got)
	}

	{
		val := &OAuthProviderConfiguration{}

		err := val.ValidateOAuth()
		require.Error(t, err)
		require.Contains(t, err.Error(), "provider is not enabled")

		val.Enabled = true
		err = val.ValidateOAuth()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing OAuth client ID")

		val.ClientID = []string{"a"}
		err = val.ValidateOAuth()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing OAuth secret")

		val.Secret = "a"
		err = val.ValidateOAuth()
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing redirect URI")

		val.RedirectURI = "a"
		err = val.ValidateOAuth()
		require.NoError(t, err)
	}

	{
		val := &GlobalConfiguration{}
		err := val.ApplyDefaults()
		require.Error(t, err)
		require.Contains(t, err.Error(),
			`failed to initialize *jwk.symmetricKey from []uint8:`+
				` non-empty []byte key required`)
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
			},
		}
		err := val.ApplyDefaults()
		require.NoError(t, err)
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
				KeyID:  "a",
			},
		}

		sentinel := errors.New("sentinel")
		key := helpToMockKey(t, sentinel)
		key.n = 0

		err := val.applyDefaultsJWTPrivateKey(key)
		require.Error(t, err)
		require.Contains(t, err.Error(), "sentinel")
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
				KeyID:  "a",
			},
		}

		sentinel := errors.New("sentinel")
		key := helpToMockKey(t, sentinel)
		key.n = -1
		key.alg = jwa.SignatureAlgorithm("")

		err := val.applyDefaultsJWTPrivateKey(key)
		require.Error(t, err)
		require.Contains(t, err.Error(), "sentinel")
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
				KeyID:  "a",
			},
		}

		sentinel := errors.New("sentinel")
		key := helpToMockKey(t, sentinel)
		key.n = -2
		key.alg = jwa.SignatureAlgorithm("")

		err := val.applyDefaultsJWTPrivateKey(key)
		require.Error(t, err)
		require.Contains(t, err.Error(), "sentinel")
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
				KeyID:  "a",
			},
		}

		sentinel := errors.New("sentinel")
		key := helpToMockKey(t, sentinel)
		key.n = -3
		key.ops = jwk.KeyOperationList{}
		key.alg = jwa.SignatureAlgorithm("")

		err := val.applyDefaultsJWTPrivateKey(key)
		require.Error(t, err)
		require.Contains(t, err.Error(), "sentinel")
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
				KeyID:  "a",
			},
		}

		sentinel := errors.New("sentinel")
		key := helpToMockKey(t, sentinel)
		key.n = -4
		key.alg = jwa.SignatureAlgorithm("")

		err := val.applyDefaultsJWTPrivateKey(key)
		require.Error(t, err)
		require.Contains(t, err.Error(), "sentinel")
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
			},
			Mailer: MailerConfiguration{
				Autoconfirm:                 true,
				AllowUnverifiedEmailSignIns: true,
			},
		}
		err := val.ApplyDefaults()
		require.Error(t, err)
		require.Contains(t, err.Error(), `cannot enable both `+
			`GOTRUE_MAILER_AUTOCONFIRM and `+
			`GOTRUE_MAILER_ALLOW_UNVERIFIED_EMAIL_SIGN_INS`)
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
			},
			Sms: SmsProviderConfiguration{
				TestOTP: map[string]string{"13334444": "123456"},
			},
		}
		err := val.ApplyDefaults()
		require.NoError(t, err)
	}
	{
		val := &GlobalConfiguration{
			JWT: JWTConfiguration{
				Secret: "a",
			},
			URIAllowList: []string{
				"http://localhost/*/**",
			},
		}
		err := val.ApplyDefaults()
		require.NoError(t, err)
	}
}

func TestLoading(t *testing.T) {
	defer os.Clearenv()

	{
		os.Clearenv()
		err := LoadFile("abc")
		require.Error(t, err)
	}

	{
		os.Clearenv()
		err := LoadFile("")
		require.NoError(t, err)
	}

	{
		os.Clearenv()
		err := loadEnvironment("abc")
		require.Error(t, err)
	}

	{
		os.Clearenv()
		err := loadEnvironment("")
		require.NoError(t, err)
	}

	{
		os.Clearenv()
		err := LoadDirectory("")
		require.NoError(t, err)
	}

	{
		os.Clearenv()
		err := LoadDirectory("__invalid__")
		require.Error(t, err)
		require.Contains(t, err.Error(),
			`open __invalid__: no such file or directory`)
	}

	{
		os.Clearenv()
		err := LoadDirectory("../reloader/testdata")
		require.NoError(t, err)
	}

	{
		os.Clearenv()
		err := loadDirectoryPaths("__invalid__")
		require.Error(t, err)
	}

	{
		os.Clearenv()
		cfg, err := LoadGlobalFromEnv()
		require.Error(t, err)
		require.Nil(t, cfg)
	}
}

func toPtr[T any](v T) *T {
	return &(&([1]T{T(v)}))[0]
}
