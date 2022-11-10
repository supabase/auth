package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"unicode/utf8"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/observability"
	"github.com/netlify/gotrue/storage"
)

var (
	ssoProviderResourceIDPattern = regexp.MustCompile("(?i)^[a-z0-9_-]{5,256}$")
)

// loadSSOProvider looks for an idp_id parameter in the URL route and loads the SSO provider
// with that ID (or resource ID) and adds it to the context.
func (a *API) loadSSOProvider(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	var err error
	var provider *models.SSOProvider

	idpParam := chi.URLParam(r, "idp_id")

	if idpID, err := uuid.FromString(idpParam); err == nil {
		// idpParam is a UUIDv4
		provider, err = models.FindSSOProviderByID(db, idpID)
		if err != nil {
			if !models.IsNotFoundError(err) {
				return nil, internalServerError("Database error finding SSO Identity Provider").WithInternalError(err)
			}
			// not found with the ID, maybe it's a ResourceID?
		}
	}

	if provider == nil {
		// provider wasn't found, consider idpParam is a resource ID

		if !ssoProviderResourceIDPattern.MatchString(idpParam) {
			// it is definitely not a resource ID
			return nil, notFoundError("SSO Identity Provider not found")
		}

		provider, err = models.FindSSOProviderByResourceID(db, idpParam)
		if err != nil {
			if models.IsNotFoundError(err) {
				return nil, notFoundError("SSO Identity Provider not found")
			} else {
				return nil, internalServerError("Database error finding SSO Identity Provider").WithInternalError(err)
			}
		}
	}

	observability.LogEntrySetField(r, "sso_provider_id", provider.ID.String())
	if provider.ResourceID != nil {
		resourceID := *provider.ResourceID
		observability.LogEntrySetField(r, "sso_provider_resource_id", resourceID)
	}

	return withSSOProvider(r.Context(), provider), nil
}

// adminSSOProvidersList lists all SAML SSO Identity Providers in the system. Does
// not deal with pagination at this time.
func (a *API) adminSSOProvidersList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	providers, err := models.FindAllSAMLProviders(db)
	if err != nil {
		return err
	}

	for i := range providers {
		// remove metadata XML so that the returned JSON is not ginormous
		providers[i].SAMLProvider.MetadataXML = ""
	}

	return sendJSON(w, http.StatusOK, map[string]interface{}{
		"items": providers,
	})
}

type CreateSSOProviderParams struct {
	ResourceID string `json:"resource_id"`
	Type       string `json:"type"`

	MetadataURL      string                      `json:"metadata_url"`
	MetadataXML      string                      `json:"metadata_xml"`
	Domains          []string                    `json:"domains"`
	AttributeMapping models.SAMLAttributeMapping `json:"attribute_mapping"`
}

func (p *CreateSSOProviderParams) validate(forUpdate bool) error {
	if !forUpdate && p.Type != "saml" {
		return badRequestError("Only 'saml' supported for SSO provider type")
	} else if p.ResourceID != "" && !ssoProviderResourceIDPattern.MatchString(p.ResourceID) {
		return badRequestError("Resource IDs can only contain letters, digits, dashes and underscores, have a minimum lenth of 5 and a maximum of 256")
	} else if p.MetadataURL != "" && p.MetadataXML != "" {
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

	// TODO validate p.AttributeMapping
	// TODO validate domains

	return nil
}

func (p *CreateSSOProviderParams) metadata(ctx context.Context) ([]byte, *saml.EntityDescriptor, error) {
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// adminSSOProvidersCreate creates a new SAML Identity Provider in the system.
func (a *API) adminSSOProvidersCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	body, err := getBodyBytes(r)
	if err != nil {
		return internalServerError("Unable to read request body").WithInternalError(err)
	}

	var params CreateSSOProviderParams
	if err := json.Unmarshal(body, &params); err != nil {
		return badRequestError("Unable to parse JSON").WithInternalError(err)
	}

	if err := params.validate(false /* <- forUpdate */); err != nil {
		return err
	}

	rawMetadata, metadata, err := params.metadata(ctx)
	if err != nil {
		return err
	}

	if params.ResourceID != "" {
		if _, err := models.FindSSOProviderByResourceID(db, params.ResourceID); err != nil {
			if !models.IsNotFoundError(err) {
				return internalServerError("Unable to find SSO provider by resource ID").WithInternalError(err)
			}
		} else {
			return badRequestError("A SSO provider with this resource ID (%s) already exists", params.ResourceID)
		}
	}

	existingProvider, err := models.FindSAMLProviderByEntityID(db, metadata.EntityID)
	if err != nil && !models.IsNotFoundError(err) {
		return err
	}
	if existingProvider != nil {
		return badRequestError("SAML Identity Provider with this EntityID (%s) already exists", metadata.EntityID)
	}

	provider := &models.SSOProvider{
		// TODO handle Name, Description, Attribute Mapping
		SAMLProvider: models.SAMLProvider{
			EntityID:    metadata.EntityID,
			MetadataXML: string(rawMetadata),
		},
	}

	if params.ResourceID != "" {
		provider.ResourceID = &params.ResourceID
	}

	if params.MetadataURL != "" {
		provider.SAMLProvider.MetadataURL = &params.MetadataURL
	}

	provider.SAMLProvider.AttributeMapping = params.AttributeMapping

	for _, domain := range params.Domains {
		existingProvider, err := models.FindSSOProviderByDomain(db, domain)
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

	if err := db.Transaction(func(tx *storage.Connection) error {
		return tx.Eager().Create(provider)
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusCreated, provider)
}

// adminSSOProvidersGet returns an existing SAML Identity Provider in the system.
func (a *API) adminSSOProvidersGet(w http.ResponseWriter, r *http.Request) error {
	provider := getSSOProvider(r.Context())

	return sendJSON(w, http.StatusOK, provider)
}

// adminSSOProvidersUpdate updates a provider with the provided diff values.
func (a *API) adminSSOProvidersUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	body, err := getBodyBytes(r)
	if err != nil {
		return internalServerError("Unable to read request body").WithInternalError(err)
	}

	var params CreateSSOProviderParams
	if err := json.Unmarshal(body, &params); err != nil {
		return badRequestError("Unable to parse JSON").WithInternalError(err)
	}

	if err := params.validate(true /* <- forUpdate */); err != nil {
		return err
	}

	modified := false

	provider := getSSOProvider(ctx)

	if params.ResourceID != "" && (provider.ResourceID == nil || params.ResourceID != *provider.ResourceID) {
		// resource ID is being updated

		existingProvider, err := models.FindSSOProviderByResourceID(db, params.ResourceID)
		if err != nil && !models.IsNotFoundError(err) {
			return err
		}

		if existingProvider != nil {
			return badRequestError("SSO Provider Resource ID (%s) can't be updated, already assigned to another provider (%s)", params.ResourceID, existingProvider.ID.String())
		}

		provider.ResourceID = &params.ResourceID
		modified = true
	}

	if params.MetadataXML != "" || params.MetadataURL != "" {
		// metadata is being updated
		rawMetadata, metadata, err := params.metadata(ctx)
		if err != nil {
			return err
		}

		if provider.SAMLProvider.EntityID != metadata.EntityID {
			return badRequestError("SAML Metadata can be updated only if the EntityID matches for the provider; expected '%s' but got '%s'", provider.SAMLProvider.EntityID, metadata.EntityID)
		}

		if params.MetadataURL != "" {
			provider.SAMLProvider.MetadataURL = &params.MetadataURL
		}

		provider.SAMLProvider.MetadataXML = string(rawMetadata)
		modified = true
	}

	var createDomains []string
	keepDomains := make(map[string]bool)

	for _, domain := range params.Domains {
		existingProvider, err := models.FindSSOProviderByDomain(db, domain)
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

	var updatedDomains []models.SSODomain

	for _, domain := range provider.SSODomains {
		if keepDomains[domain.Domain] {
			updatedDomains = append(updatedDomains, domain)
		}
	}

	for _, domain := range createDomains {
		updatedDomains = append(updatedDomains, models.SSODomain{
			Domain: domain,
		})
	}

	modified = modified || len(createDomains) > 0

	provider.SSODomains = updatedDomains

	if !provider.SAMLProvider.AttributeMapping.Equal(&params.AttributeMapping) {
		modified = true
		provider.SAMLProvider.AttributeMapping = params.AttributeMapping
	}

	if modified {
		if err := db.Transaction(func(tx *storage.Connection) error {
			return tx.Eager().Update(provider)
		}); err != nil {
			return err
		}
	}

	return sendJSON(w, http.StatusOK, provider)
}

// adminSSOProvidersDelete deletes a SAML identity provider.
func (a *API) adminSSOProvidersDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	provider := getSSOProvider(ctx)

	if err := db.Transaction(func(tx *storage.Connection) error {
		return tx.Eager().Destroy(provider)
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, provider)
}
