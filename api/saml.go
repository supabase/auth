package api

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// getSAMLServiceProvider generates a new service provider object with the
// (optionally) provided descriptor (metadata) for the identity provider.
func (a *API) getSAMLServiceProvider(identityProvider *saml.EntityDescriptor) *saml.ServiceProvider {
	externalURL, err := url.ParseRequestURI(a.config.API.ExternalURL)
	if err != nil {
		panic(err)
	}

	externalURL.Path = strings.TrimSuffix(externalURL.Path, "/")
	externalURL.Path += "/auth/v1/"

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
