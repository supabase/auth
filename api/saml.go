package api

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/netlify/gotrue/api/provider"
	"github.com/netlify/gotrue/models"
)

// getSAMLServiceProvider generates a new service provider object with the
// (optionally) provided descriptor (metadata) for the identity provider.
func (a *API) getSAMLServiceProvider(identityProvider *saml.EntityDescriptor) *saml.ServiceProvider {
	externalURL, err := url.ParseRequestURI(a.config.API.ExternalURL)
	if err != nil {
		// this should not fail as a.config should have been validated using #Validate()
		panic(err)
	}

	provider := samlsp.DefaultServiceProvider(samlsp.Options{
		URL:         *externalURL,
		Key:         a.config.SAML.RSAPrivateKey,
		Certificate: a.config.SAML.Certificate,
		SignRequest: true,
	})

	return &provider
}

// SAMLMetadata serves GoTrue's SAML Service Provider metadata file.
func (a *API) SAMLMetadata(w http.ResponseWriter, r *http.Request) error {
	serviceProvider := a.getSAMLServiceProvider(nil)

	metadata := serviceProvider.Metadata()

	metadataXML, err := xml.Marshal(metadata)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Cache-Control", "public, max-age=600") // cache at CDN for 10 minutes
	_, err = w.Write(metadataXML)

	return err
}

// samlCallback implements the main Assertion Consumer Service endpoint behavior.
func (a *API) samlCallback(ctx context.Context, r *http.Request) (*provider.UserProvidedData, error) {
	if r.FormValue("SAMLart") != "" {
		// TODO: SAML Artifact callbacks are only possible when you can
		// identify the IdP via RelayState i.e. only the SP initiated
		// flow is supported
		return nil, badRequestError("SAML Response with artifacts not supported at this time")
	}

	samlResponse := r.FormValue("SAMLResponse")
	if samlResponse == "" {
		return nil, badRequestError("SAMLResponse is missing")
	}

	responseXML, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, badRequestError("SAMLResponse is not a valid Base64 string")
	}

	var peekAssertion saml.Assertion
	err = xml.Unmarshal(responseXML, peekAssertion)
	if err != nil {
		return nil, badRequestError("SAMLResponse is not a valid XML SAML assertion")
	}

	entityId := peekAssertion.Issuer.Value

	ssoProvider, err := models.FindSAMLProviderForEntityID(a.db, entityId)
	if err != nil {
		return nil, err
	}

	if ssoProvider == nil {
		return nil, badRequestError("SAML Assertion has unrecognized Issuer")
	}

	idpMetadata, err := samlsp.ParseMetadata([]byte(ssoProvider.SAMLProvider.MetadataXML))
	if err != nil {
		return nil, err
	}

	// TODO: fetch new metadata if possible when validUntil < time.Now()

	serviceProvider := a.getSAMLServiceProvider(idpMetadata)
	assertion, err := serviceProvider.ParseResponse(r, nil)
	if err != nil {
		return nil, badRequestError("SAML Assertion is not valid")
	}

	var email string

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if attr.Name == "email" {
				email = attr.Values[0].Value
				break
			}
		}
	}

	return &provider.UserProvidedData{
		Emails: []provider.Email{
			{
				Email:    email,
				Verified: true,
				Primary:  true,
			},
		},
	}, nil
}
