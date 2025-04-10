package api

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// getSAMLServiceProvider generates a new service provider object with the
// (optionally) provided descriptor (metadata) for the identity provider.
func (a *API) getSAMLServiceProvider(identityProvider *saml.EntityDescriptor, idpInitiated bool) *saml.ServiceProvider {
	var externalURL *url.URL

	if a.config.SAML.ExternalURL != "" {
		url, err := url.ParseRequestURI(a.config.SAML.ExternalURL)
		if err != nil {
			// this should not fail as a.config should have been validated using #Validate()
			panic(err)
		}

		externalURL = url
	} else {
		url, err := url.ParseRequestURI(a.config.API.ExternalURL)
		if err != nil {
			// this should not fail as a.config should have been validated using #Validate()
			panic(err)
		}

		externalURL = url
	}

	if !strings.HasSuffix(externalURL.Path, "/") {
		externalURL.Path += "/"
	}

	externalURL.Path += "sso/"

	provider := samlsp.DefaultServiceProvider(samlsp.Options{
		URL:               *externalURL,
		Key:               a.config.SAML.RSAPrivateKey,
		Certificate:       a.config.SAML.Certificate,
		SignRequest:       true,
		AllowIDPInitiated: idpInitiated,
		IDPMetadata:       identityProvider,
	})

	provider.AuthnNameIDFormat = saml.PersistentNameIDFormat

	return &provider
}

// SAMLMetadata serves GoTrue's SAML Service Provider metadata file.
func (a *API) SAMLMetadata(w http.ResponseWriter, r *http.Request) error {
	serviceProvider := a.getSAMLServiceProvider(nil, true)

	metadata := serviceProvider.Metadata()

	if r.FormValue("download") == "true" {
		// 5 year expiration, comparable to what GSuite does
		metadata.ValidUntil = time.Now().UTC().AddDate(5, 0, 0)
	}

	for i := range metadata.SPSSODescriptors {
		// we set this to false since the IdP initiated flow can only
		// sign the Assertion, and not the full Request
		// unfortunately this is hardcoded in the crewjam library if
		// signatures (instead of encryption) are supported
		// https://github.com/crewjam/saml/blob/v0.4.8/service_provider.go#L217
		metadata.SPSSODescriptors[i].AuthnRequestsSigned = nil

		// advertize the requested NameID formats (either persistent or email address)
		metadata.SPSSODescriptors[i].NameIDFormats = []saml.NameIDFormat{
			saml.EmailAddressNameIDFormat,
			saml.PersistentNameIDFormat,
		}
	}

	for i := range metadata.SPSSODescriptors {
		spd := &metadata.SPSSODescriptors[i]

		var keyDescriptors []saml.KeyDescriptor

		for _, kd := range spd.KeyDescriptors {
			// only advertize key as usable for encryption if allowed
			if kd.Use == "signing" || (a.config.SAML.AllowEncryptedAssertions && kd.Use == "encryption") {
				keyDescriptors = append(keyDescriptors, kd)
			}
		}

		spd.KeyDescriptors = keyDescriptors
	}

	metadataXML, err := xml.Marshal(metadata)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Cache-Control", "public, max-age=600") // cache at CDN for 10 minutes

	if r.FormValue("download") == "true" {
		w.Header().Set("Content-Disposition", "attachment; filename=\"metadata.xml\"")
	}

	_, err = w.Write(metadataXML)

	return err
}
