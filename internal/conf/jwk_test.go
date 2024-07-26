package conf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	// array of JWKs containing 4 keys
	gotrueJwtKeys := `[{"kty":"oct","k":"9Sj51i2YvfY85NJZFD6rAl9fKDxSKjFgW6W6ZXOJLnU","kid":"f90202bc-413a-4db3-8e04-b70a02a65669","key_ops":["verify"],"alg":"HS256"},{"kty":"RSA","n":"4slQjr-XoU6I1KXFWOeeJi387RIUxjhyzXX3GUVNb75a0SPKoGShlJEbpvuXqkDLGDweLcIZy-01nqgjSzMY_tUO3L78MxVfIVn7MByJ4_zbrVf5rjKeAk9EEMl6pb8nKJGArph9sOwL68LLioNySt_WNo_hMfuxUuVkRagh5gLjYoQ4odkULQrgwlMcXxXNnvg0aYURUr2SDmncHNuZQ3adebRlI164mUZPPWui2fg72R7c9qhVaAEzbdG-JAuC3zn5iL4zZk-8pOwZkM7Qb_2lrcXwdTl_Qz6fMdAHz_3rggac5oeKkdvO2x7_XiUwGxIBYSghxg5BBxcyqd6WrQ","e":"AQAB","d":"FjJo7uH4aUoktO8kHhbHbY_KSdQpHDjKyc7yTS_0DWYgUfdozzubJfRDF42vI-KsXssF-NoB0wJf0uP0L8ip6G326XPuoMQRTMgcaF8j6swTwsapSOEagr7BzcECx1zpc2-ojhwbLHSvRutWDzPJkbrUccF8vRC6BsiAUG4Hapiumbot7JtJGwU8ZUhxico7_OEJ_MtkRrHByXgrOMnzNLrmViI9rzvtWOhVc8sNDzLogDDi01AP0j6WeBhbOpaZ_1BMLQ9IeeN5Iiy-7Qj-q4-8kBXIPXpYaKMFnDTmhB0GAVUFimF6ojhZNAJvV81VMHPjrEmmps0_qBfIlKAB","p":"9G7wBpiSJHAl-w47AWvW60v_hye50lte4Ep2P3KeRyinzgxtEMivzldoqirwdoyPCJWwU7nNsv7AjdXVoHFy3fJvJeV5mhArxb2zA36OS_Tr3CQXtB3OO-RFwVcG7AGO7XvA54PK28siXY2VvkG2Xn_ZrbVebJnHQprn7ddUIIE","q":"7YSaG2E_M9XpgUJ0izwKdfGew6Hz5utPUdwMWjqr81BjtLkUtQ3tGYWs2tdaRYUTK4mNFyR2MjLYnMK-F37rue4LSKitmEu2N6RD9TwzcqwiEL_vuQTC985iJ0hzUC58LcbhYtTLU3KqZXXUqaeBXEwQAWxK1NRf6rQRhOGk4C0","dp":"fOV-sfAdpI7FaW3RCp3euGYh0B6lXW4goXyKxUq8w2FrtOY2iH_zDP0u1tyP-BNENr-91Fo5V__BxfeAa7XsWqo4zuVdaDJhG24d3Wg6L2ebaOXsUrV0Hrg6SFs-hzMYpBI69FEsQ3idO65P2GJdXBX51T-6WsWMwmTCo44GR4E","dq":"O2DrJe0p38ualLYIbMaV1uaQyleyoggxzEU20VfZpPpz8rpScvEIVVkV3Z_48WhTYo8AtshmxCXyAT6uRzFzvQfFymRhAbHr2_01ABoMwp5F5eoWBCsskscFwsxaB7GXWdpefla0figscTED-WXm8SwS1Eg-bParBAIAXzgKAAE","qi":"Cezqw8ECfMmwnRXJuiG2A93lzhixHxXISvGC-qbWaRmCfetheSviZlM0_KxF6dsvrw_aNfIPa8rv1TbN-5F04v_RU1CD79QuluzXWLkZVhPXorkK5e8sUi_odzAJXOwHKQzal5ndInl4XYctDHQr8jXcFW5Un65FhPwdAC6-aek","kid":"74b1a36b-4b39-467f-976b-acc7ec600a6d","key_ops":["verify"],"alg":"RS256"},{"kty":"EC","x":"GwbnH57MUhgL14dJfayyzuI6o2_mB_Pm8xIuauHXtQs","y":"cYqN0VAcv0BC9wrg3vNgHlKhGP8ZEedUC2A8jXpaGwA","crv":"P-256","d":"4STEXq7W4UY0piCGPueMaQqAAZ5jVRjjA_b1Hq7YgmM","kid":"fa3ffc99-4635-4b19-b5c0-6d6a8d30c4eb","key_ops":["sign","verify"],"alg":"ES256"},{"crv":"Ed25519","d":"T179kXSOJHE8CNbqaI2HNdG8r3YbSoKYxNRSzTkpEcY","x":"iDYagELzmD4z6uaW7eAZLuQ9fiUlnLqtrh7AfNbiNiI","kty":"OKP","kid":"b1176272-46e4-4226-b0bd-12eef4fd7367","key_ops":["verify"],"alg":"EdDSA"}]`
	var decoder JwtKeysDecoder
	require.NoError(t, decoder.Decode(gotrueJwtKeys))
	require.Len(t, decoder, 4)

	for kid, key := range decoder {
		require.NotEmpty(t, kid)
		require.NotNil(t, key.PrivateKey)
		require.NotNil(t, key.PublicKey)
		require.NotEmpty(t, key.PublicKey.KeyOps(), "missing key_ops claim")
	}
}

func TestJWTConfiguration(t *testing.T) {
	// array of JWKs containing 4 keys
	gotrueJwtKeys := `[{"kty":"oct","k":"9Sj51i2YvfY85NJZFD6rAl9fKDxSKjFgW6W6ZXOJLnU","kid":"f90202bc-413a-4db3-8e04-b70a02a65669","key_ops":["verify"],"alg":"HS256"},{"kty":"RSA","n":"4slQjr-XoU6I1KXFWOeeJi387RIUxjhyzXX3GUVNb75a0SPKoGShlJEbpvuXqkDLGDweLcIZy-01nqgjSzMY_tUO3L78MxVfIVn7MByJ4_zbrVf5rjKeAk9EEMl6pb8nKJGArph9sOwL68LLioNySt_WNo_hMfuxUuVkRagh5gLjYoQ4odkULQrgwlMcXxXNnvg0aYURUr2SDmncHNuZQ3adebRlI164mUZPPWui2fg72R7c9qhVaAEzbdG-JAuC3zn5iL4zZk-8pOwZkM7Qb_2lrcXwdTl_Qz6fMdAHz_3rggac5oeKkdvO2x7_XiUwGxIBYSghxg5BBxcyqd6WrQ","e":"AQAB","d":"FjJo7uH4aUoktO8kHhbHbY_KSdQpHDjKyc7yTS_0DWYgUfdozzubJfRDF42vI-KsXssF-NoB0wJf0uP0L8ip6G326XPuoMQRTMgcaF8j6swTwsapSOEagr7BzcECx1zpc2-ojhwbLHSvRutWDzPJkbrUccF8vRC6BsiAUG4Hapiumbot7JtJGwU8ZUhxico7_OEJ_MtkRrHByXgrOMnzNLrmViI9rzvtWOhVc8sNDzLogDDi01AP0j6WeBhbOpaZ_1BMLQ9IeeN5Iiy-7Qj-q4-8kBXIPXpYaKMFnDTmhB0GAVUFimF6ojhZNAJvV81VMHPjrEmmps0_qBfIlKAB","p":"9G7wBpiSJHAl-w47AWvW60v_hye50lte4Ep2P3KeRyinzgxtEMivzldoqirwdoyPCJWwU7nNsv7AjdXVoHFy3fJvJeV5mhArxb2zA36OS_Tr3CQXtB3OO-RFwVcG7AGO7XvA54PK28siXY2VvkG2Xn_ZrbVebJnHQprn7ddUIIE","q":"7YSaG2E_M9XpgUJ0izwKdfGew6Hz5utPUdwMWjqr81BjtLkUtQ3tGYWs2tdaRYUTK4mNFyR2MjLYnMK-F37rue4LSKitmEu2N6RD9TwzcqwiEL_vuQTC985iJ0hzUC58LcbhYtTLU3KqZXXUqaeBXEwQAWxK1NRf6rQRhOGk4C0","dp":"fOV-sfAdpI7FaW3RCp3euGYh0B6lXW4goXyKxUq8w2FrtOY2iH_zDP0u1tyP-BNENr-91Fo5V__BxfeAa7XsWqo4zuVdaDJhG24d3Wg6L2ebaOXsUrV0Hrg6SFs-hzMYpBI69FEsQ3idO65P2GJdXBX51T-6WsWMwmTCo44GR4E","dq":"O2DrJe0p38ualLYIbMaV1uaQyleyoggxzEU20VfZpPpz8rpScvEIVVkV3Z_48WhTYo8AtshmxCXyAT6uRzFzvQfFymRhAbHr2_01ABoMwp5F5eoWBCsskscFwsxaB7GXWdpefla0figscTED-WXm8SwS1Eg-bParBAIAXzgKAAE","qi":"Cezqw8ECfMmwnRXJuiG2A93lzhixHxXISvGC-qbWaRmCfetheSviZlM0_KxF6dsvrw_aNfIPa8rv1TbN-5F04v_RU1CD79QuluzXWLkZVhPXorkK5e8sUi_odzAJXOwHKQzal5ndInl4XYctDHQr8jXcFW5Un65FhPwdAC6-aek","kid":"74b1a36b-4b39-467f-976b-acc7ec600a6d","key_ops":["verify"],"alg":"RS256"},{"kty":"EC","x":"GwbnH57MUhgL14dJfayyzuI6o2_mB_Pm8xIuauHXtQs","y":"cYqN0VAcv0BC9wrg3vNgHlKhGP8ZEedUC2A8jXpaGwA","crv":"P-256","d":"4STEXq7W4UY0piCGPueMaQqAAZ5jVRjjA_b1Hq7YgmM","kid":"fa3ffc99-4635-4b19-b5c0-6d6a8d30c4eb","key_ops":["sign","verify"],"alg":"ES256"},{"crv":"Ed25519","d":"T179kXSOJHE8CNbqaI2HNdG8r3YbSoKYxNRSzTkpEcY","x":"iDYagELzmD4z6uaW7eAZLuQ9fiUlnLqtrh7AfNbiNiI","kty":"OKP","kid":"b1176272-46e4-4226-b0bd-12eef4fd7367","key_ops":["verify"],"alg":"EdDSA"}]`
	var decoder JwtKeysDecoder
	require.NoError(t, decoder.Decode(gotrueJwtKeys))
	require.Len(t, decoder, 4)

	cases := []struct {
		desc           string
		config         JWTConfiguration
		expectedLength int
	}{
		{
			desc: "GOTRUE_JWT_KEYS is nil",
			config: JWTConfiguration{
				Secret: "testsecret",
				KeyID:  "testkeyid",
			},
			expectedLength: 1,
		},
		{
			desc: "GOTRUE_JWT_KEYS is an empty map",
			config: JWTConfiguration{
				Secret: "testsecret",
				KeyID:  "testkeyid",
				Keys:   JwtKeysDecoder{},
			},
			expectedLength: 1,
		},
		{
			desc: "Prefer GOTRUE_JWT_KEYS over GOTRUE_JWT_SECRET",
			config: JWTConfiguration{
				Secret: "testsecret",
				KeyID:  "testkeyid",
				Keys:   decoder,
			},
			expectedLength: 4,
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			globalConfig := GlobalConfiguration{
				JWT: c.config,
			}
			require.NoError(t, globalConfig.ApplyDefaults())
			require.NotEmpty(t, globalConfig.JWT.Keys)
			require.Len(t, globalConfig.JWT.Keys, c.expectedLength)
			for _, key := range globalConfig.JWT.Keys {
				// public keys should contain these require claims
				require.NotNil(t, key.PublicKey.Algorithm())
				require.NotNil(t, key.PublicKey.KeyID())
				require.NotNil(t, key.PublicKey.KeyOps())
				require.Equal(t, "sig", key.PublicKey.KeyUsage())
			}
		})
	}
}
