package api

import (
	tst "testing"
	"time"

	"encoding/xml"
	"net/http"
	"net/http/httptest"

	"github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestSAMLMetadataWithAPI(t *tst.T) {
	config, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)
	config.API.ExternalURL = "https://projectref.supabase.co/auth/v1/"
	config.SAML.Enabled = true
	config.SAML.PrivateKey = "MIIEowIBAAKCAQEAszrVveMQcSsa0Y+zN1ZFb19cRS0jn4UgIHTprW2tVBmO2PABzjY3XFCfx6vPirMAPWBYpsKmXrvm1tr0A6DZYmA8YmJd937VUQ67fa6DMyppBYTjNgGEkEhmKuszvF3MARsIKCGtZqUrmS7UG4404wYxVppnr2EYm3RGtHlkYsXu20MBqSDXP47bQP+PkJqC3BuNGk3xt5UHl2FSFpTHelkI6lBynw16B+lUT1F96SERNDaMqi/TRsZdGe5mB/29ngC/QBMpEbRBLNRir5iUevKS7Pn4aph9Qjaxx/97siktK210FJT23KjHpgcUfjoQ6BgPBTLtEeQdRyDuc/CgfwIDAQABAoIBAGYDWOEpupQPSsZ4mjMnAYJwrp4ZISuMpEqVAORbhspVeb70bLKonT4IDcmiexCg7cQBcLQKGpPVM4CbQ0RFazXZPMVq470ZDeWDEyhoCfk3bGtdxc1Zc9CDxNMs6FeQs6r1beEZug6weG5J/yRn/qYxQife3qEuDMl+lzfl2EN3HYVOSnBmdt50dxRuX26iW3nqqbMRqYn9OHuJ1LvRRfYeyVKqgC5vgt/6Tf7DAJwGe0dD7q08byHV8DBZ0pnMVU0bYpf1GTgMibgjnLjK//EVWafFHtN+RXcjzGmyJrk3+7ZyPUpzpDjO21kpzUQLrpEkkBRnmg6bwHnSrBr8avECgYEA3pq1PTCAOuLQoIm1CWR9/dhkbJQiKTJevlWV8slXQLR50P0WvI2RdFuSxlWmA4xZej8s4e7iD3MYye6SBsQHygOVGc4efvvEZV8/XTlDdyj7iLVGhnEmu2r7AFKzy8cOvXx0QcLg+zNd7vxZv/8D3Qj9Jje2LjLHKM5n/dZ3RzUCgYEAzh5Lo2anc4WN8faLGt7rPkGQF+7/18ImQE11joHWa3LzAEy7FbeOGpE/vhOv5umq5M/KlWFIRahMEQv4RusieHWI19ZLIP+JwQFxWxS+cPp3xOiGcquSAZnlyVSxZ//dlVgaZq2o2MfrxECcovRlaknl2csyf+HjFFwKlNxHm2MCgYAr//R3BdEy0oZeVRndo2lr9YvUEmu2LOihQpWDCd0fQw0ZDA2kc28eysL2RROte95r1XTvq6IvX5a0w11FzRWlDpQ4J4/LlcQ6LVt+98SoFwew+/PWuyLmxLycUbyMOOpm9eSc4wJJZNvaUzMCSkvfMtmm5jgyZYMMQ9A2Ul/9SQKBgB9mfh9mhBwVPIqgBJETZMMXOdxrjI5SBYHGSyJqpT+5Q0vIZLfqPrvNZOiQFzwWXPJ+tV4Mc/YorW3rZOdo6tdvEGnRO6DLTTEaByrY/io3/gcBZXoSqSuVRmxleqFdWWRnB56c1hwwWLqNHU+1671FhL6pNghFYVK4suP6qu4BAoGBAMk+VipXcIlD67mfGrET/xDqiWWBZtgTzTMjTpODhDY1GZck1eb4CQMP5j5V3gFJ4cSgWDJvnWg8rcz0unz/q4aeMGl1rah5WNDWj1QKWMS6vJhMHM/rqN1WHWR0ZnV83svYgtg0zDnQKlLujqW4JmGXLMU7ur6a+e6lpa1fvLsP"
	config.API.MaxRequestDuration = 5 * time.Second

	require.NoError(t, config.ApplyDefaults())
	require.NoError(t, config.SAML.PopulateFields(config.API.ExternalURL))

	require.NotNil(t, config.SAML.Certificate)

	api := NewAPI(config, nil)

	// Setup request
	req := httptest.NewRequest(http.MethodGet, "http://localhost/sso/saml/metadata", nil)

	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, w.Code, http.StatusOK)

	metadata := saml.EntityDescriptor{}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &metadata))

	require.Equal(t, metadata.EntityID, "https://projectref.supabase.co/auth/v1/sso/saml/metadata")
	require.Equal(t, len(metadata.SPSSODescriptors), 1)

	require.Nil(t, metadata.SPSSODescriptors[0].AuthnRequestsSigned)
	require.True(t, *(metadata.SPSSODescriptors[0].WantAssertionsSigned))

	require.Equal(t, len(metadata.SPSSODescriptors[0].AssertionConsumerServices), 2)
	require.Equal(t, metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location, "https://projectref.supabase.co/auth/v1/sso/saml/acs")
	require.Equal(t, metadata.SPSSODescriptors[0].AssertionConsumerServices[1].Location, "https://projectref.supabase.co/auth/v1/sso/saml/acs")
	require.Equal(t, len(metadata.SPSSODescriptors[0].SingleLogoutServices), 1)
	require.Equal(t, metadata.SPSSODescriptors[0].SingleLogoutServices[0].Location, "https://projectref.supabase.co/auth/v1/sso/saml/slo")

	require.Equal(t, len(metadata.SPSSODescriptors[0].KeyDescriptors), 1)
	require.Equal(t, metadata.SPSSODescriptors[0].KeyDescriptors[0].Use, "signing")

	require.Equal(t, len(metadata.SPSSODescriptors[0].NameIDFormats), 2)
	require.Equal(t, metadata.SPSSODescriptors[0].NameIDFormats[0], saml.EmailAddressNameIDFormat)
	require.Equal(t, metadata.SPSSODescriptors[0].NameIDFormats[1], saml.PersistentNameIDFormat)
}
