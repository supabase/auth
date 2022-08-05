package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"unicode/utf8"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/api/provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// loadSAMLIdP looks for an idp_id parameter in the URL route and loads the SAML SSO provider
// with that ID and adds it to the context.
func (a *API) loadSAMLIdP(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	idpID, err := uuid.FromString(chi.URLParam(r, "idp_id"))
	if err != nil {
		return nil, badRequestError("idp_id must be an UUID")
	}

	logEntrySetField(r, "sso_provider_id", idpID)

	provider, err := models.FindSAMLProviderByID(a.db, idpID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError("SAML Identity Provider not found")
		}
		return nil, internalServerError("Database error finding SAML Identity Provider").WithInternalError(err)
	}

	return withSSOProvider(r.Context(), provider), nil
}

// getSAMLServiceProvider generates a new service provider object with the
// (optionally) provided descriptor (metadata) for the identity provider.
func (a *API) getSAMLServiceProvider(identityProvider *saml.EntityDescriptor) *saml.ServiceProvider {
	externalURL, err := url.ParseRequestURI(a.config.API.ExternalURL)
	if err != nil {
		// this should not fail as a.config should have been validated using #Validate()
		panic(err)
	}

	provider := samlsp.DefaultServiceProvider(samlsp.Options{
		URL:               *externalURL,
		Key:               a.config.SAML.RSAPrivateKey,
		Certificate:       a.config.SAML.Certificate,
		SignRequest:       true,
		AllowIDPInitiated: true,
		IDPMetadata:       identityProvider,
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

	var peekResponse saml.Response
	err = xml.Unmarshal(responseXML, &peekResponse)
	if err != nil {
		return nil, badRequestError("SAMLResponse is not a valid XML SAML assertion")
	}

	entityId := peekResponse.Issuer.Value

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
			if attr.Name == "mail" {
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

// adminListSAMLIdPs lists all SAML SSO Identity Providers in the system. Does
// not deal with pagination at this time.
func (a *API) adminListSAMLIdPs(w http.ResponseWriter, r *http.Request) error {
	providers, err := models.FindAllSAMLProviders(a.db)
	if err != nil {
		return err
	}

	for i := range providers {
		// remove metadata XML so that the returned JSON is not ginormous
		providers[i].SAMLProvider.MetadataXML = ""
	}

	return sendJSON(w, http.StatusOK, providers)
}

type CreateSAMLIdPParams struct {
	Name             string      `json:"name"`
	Description      string      `json:"description"`
	MetadataURL      string      `json:"metadata_url"`
	MetadataXML      string      `json:"metadata_xml"`
	Domains          []string    `json:"domains"`
	AttributeMapping interface{} `json:"attribute_mapping"`
}

func (p *CreateSAMLIdPParams) validate(forUpdate bool) error {
	if p.MetadataURL != "" && p.MetadataXML != "" {
		return badRequestError("Only one of metadata_xml or metadata_url needs to be set")
	} else if !forUpdate && p.MetadataURL == "" && p.MetadataXML == "" {
		return badRequestError("Either metadata_xml or metadata_url must be set")
	} else if p.MetadataURL != "" {
		metadataURL, err := url.ParseRequestURI(p.MetadataURL)
		if err != nil {
			return badRequestError("metadata_url is not a valid URL")
		}

		if metadataURL.Scheme != "https" {
			return badRequestError("metadata_url is not a HTTPS URL")
		}
	}

	return nil
}

func (p *CreateSAMLIdPParams) metadata(ctx context.Context) ([]byte, *saml.EntityDescriptor, error) {
	var rawMetadata []byte
	var err error

	if p.MetadataXML != "" {
		rawMetadata = []byte(p.MetadataXML)
	} else if p.MetadataURL != "" {
		rawMetadata, err = fetchSAMLMetadata(ctx, p.MetadataURL)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// impossible situation if you called validate() prior
		return nil, nil, nil
	}

	metadata, err := parseSAMLMetadata(rawMetadata)
	if err != nil {
		return nil, nil, err
	}

	return rawMetadata, metadata, nil
}

func parseSAMLMetadata(rawMetadata []byte) (*saml.EntityDescriptor, error) {
	if !utf8.Valid(rawMetadata) {
		return nil, badRequestError("SAML Metadata XML contains invalid UTF-8 characters, which are not supported at this time")
	}

	metadata, err := samlsp.ParseMetadata(rawMetadata)
	if err != nil {
		return nil, err
	}

	if metadata.EntityID == "" {
		return nil, badRequestError("SAML Metadata does not contain an EntityID")
	}

	if len(metadata.IDPSSODescriptors) < 1 {
		return nil, badRequestError("SAML Metadata does not contain any IDPSSODescriptor")
	}

	if len(metadata.IDPSSODescriptors) > 1 {
		return nil, badRequestError("SAML Metadata contains multiple IDPSSODescriptors")
	}

	return metadata, nil
}

func fetchSAMLMetadata(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, badRequestError("Unable to create a request to metadata_url").WithInternalError(err)
	}

	req = req.WithContext(ctx)

	req.Header.Set("Accept", "application/xml;charset=UTF-8")
	req.Header.Set("Accept-Charset", "UTF-8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, badRequestError("HTTP %v error fetching SAML Metadata from URL '%s'", resp.StatusCode, url)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// adminCreateSAMLIdP creates a new SAML Identity Provider in the system.
func (a *API) adminCreateSAMLIdP(w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()

	ctx := r.Context()

	var params CreateSAMLIdPParams

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&params); err != nil {
		return badRequestError("Bad JSON")
	}

	if err := params.validate(false /* <- forUpdate */); err != nil {
		return err
	}

	rawMetadata, metadata, err := params.metadata(ctx)
	if err != nil {
		return err
	}

	existingProvider, err := models.FindSAMLProviderForEntityID(a.db, metadata.EntityID)
	if err != nil && !models.IsNotFoundError(err) {
		return err
	}
	if existingProvider != nil {
		return badRequestError("SAML Identity Provider with this EntityID (%s) has already been added (%s)", metadata.EntityID, existingProvider.ID.String())
	}

	provider := &models.SSOProvider{
		// TODO handle Name, Description, Attribute Mapping
		SAMLProvider: models.SAMLProvider{
			EntityID:    metadata.EntityID,
			MetadataURL: params.MetadataURL,
			MetadataXML: string(rawMetadata),
		},
	}

	for _, domain := range params.Domains {
		// TODO validate domain

		existingProvider, err := models.FindSSOProviderByDomain(a.db, domain)
		if err != nil && !models.IsNotFoundError(err) {
			return err
		}
		if existingProvider != nil {
			return badRequestError("SSO Domain '%s' is already assigned to an SSO identity provider (%s)", domain, existingProvider.ID.String())
		}

		provider.SSODomains = append(provider.SSODomains, models.SSODomain{
			Domain: domain,
		})
	}

	if err := a.db.Transaction(func(tx *storage.Connection) error {
		return tx.Eager().Create(provider)
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusCreated, provider)
}

// adminGetSAMLIdP returns an existing SAML Identity Provider in the system.
func (a *API) adminGetSAMLIdP(w http.ResponseWriter, r *http.Request) error {
	provider := getSSOProvider(r.Context())

	return sendJSON(w, http.StatusOK, provider)
}

// adminUpdateSAMLIdP updates a provider with the provided diff values.
func (a *API) adminUpdateSAMLIdP(w http.ResponseWriter, r *http.Request) error {
	defer r.Body.Close()

	ctx := r.Context()

	var params CreateSAMLIdPParams

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&params); err != nil {
		return badRequestError("Bad JSON")
	}

	if err := params.validate(true /* <- forUpdate */); err != nil {
		return err
	}

	provider := getSSOProvider(ctx)

	dirty := false

	if params.MetadataXML != "" || params.MetadataURL != "" {
		// metadata is being updated
		rawMetadata, metadata, err := params.metadata(ctx)
		if err != nil {
			return err
		}

		if provider.SAMLProvider.EntityID != metadata.EntityID {
			return badRequestError("SAML Metadata can be updated only if the EntityID matches for the provider; expected '%s' but got '%s'", provider.SAMLProvider.EntityID, metadata.EntityID)
		}

		provider.SAMLProvider.MetadataURL = params.MetadataURL
		provider.SAMLProvider.MetadataXML = string(rawMetadata)

		dirty = dirty || true
	}

	if len(params.Domains) > 1 {
		var createDomains []string
		keepDomains := make(map[string]bool)

		for _, domain := range params.Domains {
			existingProvider, err := models.FindSSOProviderByDomain(a.db, domain)
			if err != nil && !models.IsNotFoundError(err) {
				return err
			}
			if existingProvider != nil {
				if existingProvider.ID == provider.ID {
					keepDomains[domain] = true
				} else {
					return badRequestError("SSO domain '%s' already assigned to another provider (%s)", domain, existingProvider.ID.String())
				}
			} else {
				createDomains = append(createDomains, domain)
			}
		}

		dirty = dirty || len(createDomains) > 0

		var updatedDomains []models.SSODomain

		for _, domain := range provider.SSODomains {
			if keepDomains[domain.Domain] {
				updatedDomains = append(updatedDomains, domain)
			} else {
				dirty = dirty || true
			}
		}

		for _, domain := range createDomains {
			updatedDomains = append(updatedDomains, models.SSODomain{
				Domain: domain,
			})
		}

		provider.SSODomains = updatedDomains
	}

	if dirty {
		if err := a.db.Transaction(func(tx *storage.Connection) error {
			return tx.Eager().Update(provider)
		}); err != nil {
			return err
		}
	}

	return sendJSON(w, http.StatusOK, provider)
}

// adminDeleteSAMLIdP deletes a SAML identity provider.
func (a *API) adminDeleteSAMLIdP(w http.ResponseWriter, r *http.Request) error {
	provider := getSSOProvider(r.Context())

	if err := a.db.Transaction(func(tx *storage.Connection) error {
		return tx.Eager().Destroy(provider)
	}); err != nil {
		return err
	}

	// TODO: destroy all sessions coming from this provider

	return sendJSON(w, http.StatusOK, provider)
}
