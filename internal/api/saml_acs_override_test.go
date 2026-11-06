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
	"github.com/supabase/auth/internal/conf/confload"
)

func samlOverrideConfig(t *tst.T, acsURL, entityID string) *conf.GlobalConfiguration {
	config, err := confload.LoadGlobal(apiTestConfig)
	require.NoError(t, err)
	config.API.ExternalURL = "https://projectref.supabase.co/auth/v1/"
	config.API.MaxRequestDuration = 5 * time.Second
	config.SAML.Enabled = true
	config.SAML.PrivateKey = samlTestPrimaryKey
	config.SAML.AcsURL = acsURL
	config.SAML.EntityID = entityID

	require.NoError(t, config.ApplyDefaults())
	require.NoError(t, config.SAML.PopulateFields(config.API.ExternalURL))
	return config
}

func samlOverrideMetadata(t *tst.T, config *conf.GlobalConfiguration) *saml.EntityDescriptor {
	api := NewAPI(config, nil)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/sso/saml/metadata", nil)
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	metadata := &saml.EntityDescriptor{}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), metadata))
	return metadata
}

func TestSAMLAcsURLOverride(t *tst.T) {
	const legacyACS = "https://auth.example.com/__/auth/handler"

	config := samlOverrideConfig(t, legacyACS, "")
	metadata := samlOverrideMetadata(t, config)

	require.Equal(t, 1, len(metadata.SPSSODescriptors))
	acs := metadata.SPSSODescriptors[0].AssertionConsumerServices
	require.Equal(t, 2, len(acs))
	require.Equal(t, legacyACS, acs[0].Location)
	require.Equal(t, legacyACS, acs[1].Location)

	require.Equal(t, "https://projectref.supabase.co/auth/v1/sso/saml/metadata", metadata.EntityID)
	require.Equal(
		t,
		"https://projectref.supabase.co/auth/v1/sso/saml/slo",
		metadata.SPSSODescriptors[0].SingleLogoutServices[0].Location,
	)
}

func TestSAMLEntityIDOverride(t *tst.T) {
	const legacyEntityID = "https://platform.example.com/saml/sp"

	config := samlOverrideConfig(t, "", legacyEntityID)
	metadata := samlOverrideMetadata(t, config)

	require.Equal(t, legacyEntityID, metadata.EntityID)
	require.Equal(
		t,
		"https://projectref.supabase.co/auth/v1/sso/saml/acs",
		metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location,
	)
}

func TestSAMLOverridesReachServiceProviderAndAuthnRequest(t *tst.T) {
	const (
		legacyACS      = "https://auth.example.com/__/auth/handler"
		legacyEntityID = "https://platform.example.com/saml/sp"
		idpSSOURL      = "https://idp.example.com/sso"
	)

	config := samlOverrideConfig(t, legacyACS, legacyEntityID)
	api := NewAPI(config, nil)
	idp := &saml.EntityDescriptor{
		EntityID: "https://idp.example.com",
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: idpSSOURL}},
		}},
	}

	sp := api.newSAMLServiceProvider(idp, false, config.SAML.RSAPrivateKey, config.SAML.Certificate)
	require.Equal(t, legacyACS, sp.AcsURL.String())
	require.Equal(t, legacyEntityID, sp.EntityID)

	authnRequest, err := sp.MakeAuthenticationRequest(idpSSOURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	require.NoError(t, err)
	require.Equal(t, legacyACS, authnRequest.AssertionConsumerServiceURL)
	require.Equal(t, legacyEntityID, authnRequest.Issuer.Value)
}

func TestSAMLOverridesUnsetKeepDerivedURLs(t *tst.T) {
	config := samlOverrideConfig(t, "", "")
	metadata := samlOverrideMetadata(t, config)

	require.Equal(t, "https://projectref.supabase.co/auth/v1/sso/saml/metadata", metadata.EntityID)
	require.Equal(
		t,
		"https://projectref.supabase.co/auth/v1/sso/saml/acs",
		metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location,
	)
}

func TestSAMLAcsURLOverrideRejectsMalformed(t *tst.T) {
	config, err := confload.LoadGlobal(apiTestConfig)
	require.NoError(t, err)
	config.SAML.Enabled = true
	config.SAML.PrivateKey = samlTestPrimaryKey
	config.SAML.AcsURL = "not a url at all"

	require.Error(t, config.SAML.Validate())
}
