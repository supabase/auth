package api

import (
	tst "testing"

	"encoding/xml"
	"net/http"
	"net/http/httptest"

	"github.com/crewjam/saml"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/models"
	"github.com/stretchr/testify/require"
)

func TestSAMLMetadataWithAPI(t *tst.T) {
	config := &conf.GlobalConfiguration{}
	config.API.ExternalURL = "https://projectref.supabase.co/auth/v1/"
	config.SAML.Enabled = true
	config.SAML.PrivateKey = "MIIEpAIBAAKCAQEA7i+IEc9ziokzITndZre0fGtCP+34ID8EPR6BOgdUnPtNr/0PSB0g0gwpcgb1GYCgqEsz5tkP0hvHOBYJJi9Q0rbxzBVz6FodNUaV0gN2LGjuJ7ISvKbmNvSjjtsbMlOY42bWIn2lVVvZX3Em0YouY+TEHae6m0P46YbM+g86LdLZA+4xU+nIssAAgqxi31prJrEt7cj9jU0vP4qqGJvGy1Z+SfjKyL3ibLLn/ES3VPK9YUNNak8t+4vRruEpDx3dXFLzezz7scT6cY1w1fUhwyZuakxruAuXL7hYisitUVcQNNh6as3GPaxBYeHCxRKGd6UvXvmid2Ji+BcyRaNJywIDAQABAoIBAQCzxipkjvi9Morl5B/onHVchzRMvldON2ICo5iT7N5/Ueo0D8POATY5c7aAeyHZqs0X2RMGhQS85/x4p6EmMgZF1JEyIWsHj6SGBo2kIrq6EETYrz4XJ72Q8xrUAypG1PQLhx3OkJkOkTHDKMtM0ofrG8quO1/MOwSPdhAWGRInbI0swhLMFuudoAca7JZUOTKEwf2ZoSSfd34T3d+JlbWwc3sI0FyLVGQk4a4Nn5nA6GcQGqNUtZV/kowGTTKLmXtl9JsIHhdDrdfUbWaTxU7kH1GI8c/N3SJLFYf4VjqvO6y/rGV0gu4kkVll6lyIiJY0H7HVID8Uluq9LriG/u4xAoGBAP8m7s3MfzLiJZcN76qOKAY6ifLdHQsCxILVtBTxWRNfbBtwBeKUuXASwBPZvrlVZY8zuvRS5IsFSmsNCykC/NN/ixme2sATQ95gIr5/99cn/VCJN1WAg+vEIKTe8vQ9/xvLRlmam5aNSb+IZK2drxiNCqY0KgK7o582s0ao40DZAoGBAO76Ki0JXchpZHm+P/S0VryvzkOfOo8NPhqVwbf16ClSKs0xh5qm2qiCoL9dT/LuP9hKNKuXITe05Tlvt2jJprVKEa7ZiWChJKoYMK49xO2bhugbD3EWfZzwPlqWkXWp9J0M2734H0BZ5C/S2uJOa6OM43JdjiDlZtv0eV0K4TlDAoGACw2NtL6SGAsx46xH4JSN6U8p4KpxcqOpDZ3iUjHuUOeGUF3280zMB63YQkPhfjfT0XNFOwZIPjl5cs+61wj5GNRimzaFdWKgQwbZGnWCsABcedun2P1bOaBiZaH+1lPFNFgG8STAbrIqKrDm45p8Fk0t0+tYkou8V85Pz9TLG2kCgYBSAjNbBS3TyqcaSDl2ZjSlx8cG2aukz6ySPvYdhRvIolPh2q9oWP4MeddkFEeNXEk4li6A+/oAPemzziyonxrAd8ydrjVAncwROv/pq3Ta/VZMbIzeCBPPOXqMZ8M/F7XD91epV26SDMcLylYm9zZlB8I9yvEtRMwJi1ningswNQKBgQDCh4dFLP5Eg9ML9pHqzD8WMfKSzoMNQtDR/hcLFZyGkilB+/lyIOCJwQLNKiF41tzq9Zb0I4WYEszqcvsVX3i6WC+D+/LsmjLDI90y99SsmNrChvAGdiClS1lgX9XmvHKaaK3/EUCdueLGP5Gfwf9NBq7VZ9Pyzw5olh1xWiehpw=="

	require.NoError(t, config.ApplyDefaults())

	require.NotNil(t, config.SAML.Certificate)

	api := NewAPI(config, nil)

	// Setup request
	req := httptest.NewRequest(http.MethodGet, "http://localhost/saml/metadata", nil)

	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, w.Code, http.StatusOK)

	t.Logf("SAML Metadata XML: %q", w.Body.Bytes())

	metadata := saml.EntityDescriptor{}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &metadata))

	require.Equal(t, metadata.EntityID, "https://projectref.supabase.co/auth/v1/saml/metadata")
	require.Equal(t, metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location, "https://projectref.supabase.co/auth/v1/saml/acs")
	require.Equal(t, metadata.SPSSODescriptors[0].AssertionConsumerServices[1].Location, "https://projectref.supabase.co/auth/v1/saml/acs")
	require.Equal(t, metadata.SPSSODescriptors[0].SingleLogoutServices[0].Location, "https://projectref.supabase.co/auth/v1/saml/slo")

	require.Equal(t, metadata.SPSSODescriptors[0].KeyDescriptors[0].Use, "encryption")
	require.Equal(t, metadata.SPSSODescriptors[0].KeyDescriptors[1].Use, "signing")
}

func TestSAMLAssertionUserID(t *tst.T) {
	type spec struct {
		xml    string
		userID string
	}

	examples := []spec{
		{
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ID="_72591c79da230cac1457d0ea0f2771ab" IssueInstant="2022-08-11T14:53:38.260Z" Version="2.0">
	<saml2:Issuer>https://example.com/saml</saml2:Issuer>
	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>
	<saml2:Subject>
		<saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="https://samltest.id/saml/idp" SPNameQualifier="http://localhost:9999/saml/metadata">transient-name-id</saml2:NameID>
		<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
			<saml2:SubjectConfirmationData Address="127.0.0.1" NotOnOrAfter="2022-08-11T14:58:38.272Z" Recipient="http://localhost:9999/saml/acs"/>
		</saml2:SubjectConfirmation>
	</saml2:Subject>
	<saml2:Conditions NotBefore="2022-08-11T14:53:38.260Z" NotOnOrAfter="2022-08-11T14:58:38.260Z">
		<saml2:AudienceRestriction>
			<saml2:Audience>http://localhost:9999/saml/metadata</saml2:Audience>
		</saml2:AudienceRestriction>
	</saml2:Conditions>
	<saml2:AuthnStatement AuthnInstant="2022-08-11T14:53:34.809Z" SessionIndex="_a5e14df3066529ca462930030712b65a">
		<saml2:SubjectLocality Address="127.0.0.1"/>
	<saml2:AuthnContext>
		<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
	</saml2:AuthnContext>
	</saml2:AuthnStatement>
	<saml2:AttributeStatement>
	</saml2:AttributeStatement>
</saml2:Assertion>
`,
			userID: "",
		},
		{
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ID="_72591c79da230cac1457d0ea0f2771ab" IssueInstant="2022-08-11T14:53:38.260Z" Version="2.0">
	<saml2:Issuer>https://example.com/saml</saml2:Issuer>
	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>
	<saml2:Subject>
		<saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" NameQualifier="https://example.com/saml" SPNameQualifier="http://localhost:9999/saml/metadata">persistent-name-id</saml2:NameID>
		<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
			<saml2:SubjectConfirmationData Address="79.125.170.79" NotOnOrAfter="2022-08-11T14:58:38.272Z" Recipient="http://localhost:9999/saml/acs"/>
		</saml2:SubjectConfirmation>
	</saml2:Subject>
	<saml2:Conditions NotBefore="2022-08-11T14:53:38.260Z" NotOnOrAfter="2022-08-11T14:58:38.260Z">
		<saml2:AudienceRestriction>
			<saml2:Audience>http://localhost:9999/saml/metadata</saml2:Audience>
		</saml2:AudienceRestriction>
	</saml2:Conditions>
	<saml2:AuthnStatement AuthnInstant="2022-08-11T14:53:34.809Z" SessionIndex="_a5e14df3066529ca462930030712b65a">
		<saml2:SubjectLocality Address="127.0.0.1"/>
	<saml2:AuthnContext>
		<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
	</saml2:AuthnContext>
	</saml2:AuthnStatement>
	<saml2:AttributeStatement>
	</saml2:AttributeStatement>
</saml2:Assertion>
`,
			userID: "persistent-name-id",
		},
		{
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ID="_72591c79da230cac1457d0ea0f2771ab" IssueInstant="2022-08-11T14:53:38.260Z" Version="2.0">
	<saml2:Issuer>https://example.com/saml</saml2:Issuer>
	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>
	<saml2:Subject>
		<saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress" NameQualifier="https://example.com/saml" SPNameQualifier="http://localhost:9999/saml/metadata">name-id@example.com</saml2:NameID>
		<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
			<saml2:SubjectConfirmationData Address="79.125.170.79" NotOnOrAfter="2022-08-11T14:58:38.272Z" Recipient="http://localhost:9999/saml/acs"/>
		</saml2:SubjectConfirmation>
	</saml2:Subject>
	<saml2:Conditions NotBefore="2022-08-11T14:53:38.260Z" NotOnOrAfter="2022-08-11T14:58:38.260Z">
		<saml2:AudienceRestriction>
			<saml2:Audience>http://localhost:9999/saml/metadata</saml2:Audience>
		</saml2:AudienceRestriction>
	</saml2:Conditions>
	<saml2:AuthnStatement AuthnInstant="2022-08-11T14:53:34.809Z" SessionIndex="_a5e14df3066529ca462930030712b65a">
		<saml2:SubjectLocality Address="127.0.0.1"/>
	<saml2:AuthnContext>
		<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
	</saml2:AuthnContext>
	</saml2:AuthnStatement>
	<saml2:AttributeStatement>
	</saml2:AttributeStatement>
</saml2:Assertion>
`,
			userID: "name-id@example.com",
		},
		{
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ID="_72591c79da230cac1457d0ea0f2771ab" IssueInstant="2022-08-11T14:53:38.260Z" Version="2.0">
	<saml2:Issuer>https://example.com/saml</saml2:Issuer>
	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>
	<saml2:Subject>
		<saml2:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress" NameQualifier="https://example.com/saml" SPNameQualifier="http://localhost:9999/saml/metadata">name-id@example.com</saml2:NameID>
		<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
			<saml2:SubjectConfirmationData Address="79.125.170.79" NotOnOrAfter="2022-08-11T14:58:38.272Z" Recipient="http://localhost:9999/saml/acs"/>
		</saml2:SubjectConfirmation>
	</saml2:Subject>
	<saml2:Conditions NotBefore="2022-08-11T14:53:38.260Z" NotOnOrAfter="2022-08-11T14:58:38.260Z">
		<saml2:AudienceRestriction>
			<saml2:Audience>http://localhost:9999/saml/metadata</saml2:Audience>
		</saml2:AudienceRestriction>
	</saml2:Conditions>
	<saml2:AuthnStatement AuthnInstant="2022-08-11T14:53:34.809Z" SessionIndex="_a5e14df3066529ca462930030712b65a">
		<saml2:SubjectLocality Address="127.0.0.1"/>
	<saml2:AuthnContext>
		<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
	</saml2:AuthnContext>
	</saml2:AuthnStatement>
	<saml2:AttributeStatement>
		<saml2:Attribute Name="urn:oasis:names:tc:SAML:attribute:subject-id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
			<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">subject-id</saml2:AttributeValue>
		</saml2:Attribute>
	</saml2:AttributeStatement>
</saml2:Assertion>
`,
			userID: "subject-id",
		},
	}

	for i, example := range examples {
		rawAssertion := saml.Assertion{}
		require.NoError(t, xml.Unmarshal([]byte(example.xml), &rawAssertion))

		assertion := SAMLAssertion{
			&rawAssertion,
		}

		userID := assertion.UserID()

		require.Equal(t, userID, example.userID, "example %d had different user ID", i)
	}
}

func TestSAMLAssertionProcessing(t *tst.T) {
	type spec struct {
		xml      string
		mapping  models.SAMLAttributeMapping
		expected map[string]interface{}
	}

	examples := []spec{
		{
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ID="_72591c79da230cac1457d0ea0f2771ab" IssueInstant="2022-08-11T14:53:38.260Z" Version="2.0">
	<saml2:AttributeStatement>
		<saml2:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
			<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">someone@example.com</saml2:AttributeValue>
		</saml2:Attribute>
	</saml2:AttributeStatement>
</saml2:Assertion>
`,
			mapping: models.SAMLAttributeMapping{
				Keys: map[string]models.SAMLAttribute{
					"email": {
						Name: "mail",
					},
				},
			},
			expected: map[string]interface{}{
				"email": "someone@example.com",
			},
		},
		{
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ID="_72591c79da230cac1457d0ea0f2771ab" IssueInstant="2022-08-11T14:53:38.260Z" Version="2.0">
	<saml2:AttributeStatement>
		<saml2:Attribute Name="http://schemas.xmlsoap.org/claims/EmailAddress" FriendlyName="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
			<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">old-soap@example.com</saml2:AttributeValue>
		</saml2:Attribute>
		<saml2:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" FriendlyName="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
			<saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">soap@example.com</saml2:AttributeValue>
		</saml2:Attribute>
	</saml2:AttributeStatement>
</saml2:Assertion>
`,
			mapping: models.SAMLAttributeMapping{
				Keys: map[string]models.SAMLAttribute{
					"email": {
						Names: []string{
							"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
							"http://schemas.xmlsoap.org/claims/EmailAddress",
						},
					},
				},
			},
			expected: map[string]interface{}{
				"email": "soap@example.com",
			},
		},
	}

	for i, example := range examples {
		rawAssertion := saml.Assertion{}
		require.NoError(t, xml.Unmarshal([]byte(example.xml), &rawAssertion))

		assertion := SAMLAssertion{
			&rawAssertion,
		}

		result := assertion.Process(example.mapping)

		require.Equal(t, result, example.expected, "example %d had different processing", i)
	}
}
