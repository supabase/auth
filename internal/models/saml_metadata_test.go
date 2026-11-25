package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Metadata wrapped in EntitiesDescriptor, as shipped by some federations.
// cacheDuration uses the XML Schema duration lexical form (PT5H), which is
// valid per saml-schema-metadata-2.0.xsd. The inner entity keeps its own
// cacheDuration so a successful parse must not drop it.
const entitiesDescriptorXSDurationMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2024-08-09T23:11:46Z" cacheDuration="PT5H">
  <md:EntityDescriptor entityID="https://idp.example.com/metadata" cacheDuration="PT1H">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    </md:IDPSSODescriptor>
  </md:EntityDescriptor>
</md:EntitiesDescriptor>`

func TestEntityDescriptorAcceptsEntitiesDescriptorXSCacheDuration(t *testing.T) {
	provider := SAMLProvider{MetadataXML: entitiesDescriptorXSDurationMetadata}

	metadata, err := provider.EntityDescriptor()
	require.NoError(t, err)
	require.Equal(t, "https://idp.example.com/metadata", metadata.EntityID)
	require.Len(t, metadata.IDPSSODescriptors, 1)
	require.Equal(t, time.Hour, metadata.CacheDuration)
	require.Equal(t, "https://idp.example.com/sso", metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location)
}
