package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

// loadSSOProvider looks for an idp_id parameter in the URL route and loads the SSO provider
// with that ID (or resource ID) and adds it to the context.
func (a *API) loadOIDCSSOProvider(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	idpParam := chi.URLParam(r, "idp_id")

	idpID, err := uuid.FromString(idpParam)
	if err != nil {
		// idpParam is not UUIDv4
		return nil, notFoundError(ErrorCodeSSOProviderNotFound, "SSO Identity Provider not found")
	}

	// idpParam is a UUIDv4
	provider, err := models.FindSSOProviderByID(db, idpID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError(ErrorCodeSSOProviderNotFound, "SSO Identity Provider not found")
		} else {
			return nil, internalServerError("Database error finding SSO Identity Provider").WithInternalError(err)
		}
	}

	observability.LogEntrySetField(r, "sso_provider_id", provider.ID.String())

	return withSSOProvider(r.Context(), provider), nil
}

// adminSSOProvidersList lists all SAML SSO Identity Providers in the system. Does
// not deal with pagination at this time.
func (a *API) adminOIDCSSOProvidersList(w http.ResponseWriter, r *http.Request) error {
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

type CreateOIDCSSOProviderParams struct {
	Type string `json:"type"`

	ClientId    string `json:"client_id"`
	Secret      string `json:"secret"`
	AuthURL     string `json:"auth_url"`
	TokenURL    string `json:"token_url"`
	UserinfoURL string `json:"userinfo_url"`
	// MetadataURL      string                      `json:"metadata_url"`
	// MetadataXML      string                      `json:"metadata_xml"`

	DiscoveryURL string `json:"discover_url"`

	Domains          []string               `json:"domains"`
	AttributeMapping models.UserDataMapping `json:"attribute_mapping"`
	// NameIDFormat     string                      `json:"name_id_format"`
}

func (p *CreateOIDCSSOProviderParams) validate(forUpdate bool) error {
	if !forUpdate && p.Type != "oidc" {
		return badRequestError(ErrorCodeValidationFailed, "Only 'oidc' supported for SSO provider type")
	}
	// } else if p.MetadataURL != "" && p.MetadataXML != "" {
	// 	return badRequestError(ErrorCodeValidationFailed, "Only one of metadata_xml or metadata_url needs to be set")
	// } else if !forUpdate && p.MetadataURL == "" && p.MetadataXML == "" {
	// 	return badRequestError(ErrorCodeValidationFailed, "Either metadata_xml or metadata_url must be set")
	// } else if p.MetadataURL != "" {
	// 	metadataURL, err := url.ParseRequestURI(p.MetadataURL)
	// 	if err != nil {
	// 		return badRequestError(ErrorCodeValidationFailed, "metadata_url is not a valid URL")
	// 	}

	// 	if metadataURL.Scheme != "https" {
	// 		return badRequestError(ErrorCodeValidationFailed, "metadata_url is not a HTTPS URL")
	// 	}
	// }

	// switch p.NameIDFormat {
	// case "",
	// 	string(saml.PersistentNameIDFormat),
	// 	string(saml.EmailAddressNameIDFormat),
	// 	string(saml.TransientNameIDFormat),
	// 	string(saml.UnspecifiedNameIDFormat):
	// 	// it's valid

	// default:
	// 	return badRequestError(ErrorCodeValidationFailed, "name_id_format must be unspecified or one of %v", strings.Join([]string{
	// 		string(saml.PersistentNameIDFormat),
	// 		string(saml.EmailAddressNameIDFormat),
	// 		string(saml.TransientNameIDFormat),
	// 		string(saml.UnspecifiedNameIDFormat),
	// 	}, ", "))
	// }

	return nil
}

func (p *CreateOIDCSSOProviderParams) metadata(ctx context.Context) (*conf.GenericOAuthProviderConfiguration, error) {
	var discover *OIDCDiscoveryResponse
	var err error

	var config *conf.GenericOAuthProviderConfiguration

	if p.DiscoveryURL != "" {
		discover, err = fetchOIDCMetadata(ctx, p.DiscoveryURL)
		if err != nil {
			return nil, err
		}
		config = &conf.GenericOAuthProviderConfiguration{
			OAuthProviderConfiguration: &conf.OAuthProviderConfiguration{
				ClientID:    []string{p.ClientId},
				Secret:      p.Secret,
				URL:         discover.Issuer,
				ApiURL:      discover.UserInfoEndpoint,
				RedirectURI: "", // TODO: figure out how to get the data
			},
			Issuer:          discover.Issuer,
			AuthURL:         discover.AuthorizationEndpoint,
			TokenURL:        discover.TokenEndpoint,
			UserInfoURL:     discover.UserInfoEndpoint,
			UserDataMapping: p.AttributeMapping.Keys,
		}

		log.Println(p.AttributeMapping)
	} else if p.DiscoveryURL == "" && true {
		config = &conf.GenericOAuthProviderConfiguration{
			OAuthProviderConfiguration: &conf.OAuthProviderConfiguration{},
		}
	} else {
		// impossible situation if you called validate() prior
		return nil, nil
	}

	// metadata, err := parseSAMLMetadata(rawMetadata)
	// if err != nil {
	// 	return nil, err
	// }

	return config, nil
}

// func parseSAMLMetadata(rawMetadata []byte) (*saml.EntityDescriptor, error) {
// 	if !utf8.Valid(rawMetadata) {
// 		return nil, badRequestError(ErrorCodeValidationFailed, "SAML Metadata XML contains invalid UTF-8 characters, which are not supported at this time")
// 	}

// 	metadata, err := samlsp.ParseMetadata(rawMetadata)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if metadata.EntityID == "" {
// 		return nil, badRequestError(ErrorCodeValidationFailed, "SAML Metadata does not contain an EntityID")
// 	}

// 	if len(metadata.IDPSSODescriptors) < 1 {
// 		return nil, badRequestError(ErrorCodeValidationFailed, "SAML Metadata does not contain any IDPSSODescriptor")
// 	}

// 	if len(metadata.IDPSSODescriptors) > 1 {
// 		return nil, badRequestError(ErrorCodeValidationFailed, "SAML Metadata contains multiple IDPSSODescriptors")
// 	}

// 	return metadata, nil
// }

type OIDCDiscoveryResponse struct {
	Issuer                 string   `json:"issuer"`
	AuthorizationEndpoint  string   `json:"authorization_endpoint"`
	TokenEndpoint          string   `json:"token_endpoint"`
	UserInfoEndpoint       string   `json:"userinfo_endpoint"`
	JWKSURI                string   `json:"jwks_uri"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
}

func fetchOIDCMetadata(ctx context.Context, issuerURL string) (*OIDCDiscoveryResponse, error) {
	// Construct the well-known URL
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", issuerURL)

	req, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, internalServerError("Unable to create a request to metadata_url").WithInternalError(err)
	}

	req = req.WithContext(ctx)

	// req.Header.Set("Accept", "application/xml;charset=UTF-8")
	req.Header.Set("Accept-Charset", "UTF-8")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer utilities.SafeClose(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, badRequestError(ErrorCodeSAMLMetadataFetchFailed, "HTTP %v error fetching OIDC Metadata from URL '%s'", resp.StatusCode, issuerURL)
	}

	// Decode the JSON response into a struct
	var config OIDCDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// adminSSOProvidersCreate creates a new SAML Identity Provider in the system.
func (a *API) adminOIDCSSOProvidersCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	params := &CreateOIDCSSOProviderParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if err := params.validate(false /* <- forUpdate */); err != nil {
		return err
	}

	log.Println("20")
	config, err := params.metadata(ctx)
	if err != nil {
		return err
	}

	log.Println("21")
	existingProvider, err := models.FindOIDCProviderByEntityID(db, params.ClientId, params.AuthURL)
	if err != nil && !models.IsNotFoundError(err) {
		return err
	}
	log.Println("22")
	if existingProvider != nil {
		return unprocessableEntityError(ErrorCodeSAMLIdPAlreadyExists, "OIDC Identity Provider with this ClientID (%s) and AuthURL (%s) already exists", params.ClientId, params.AuthURL)
	}
	log.Println("23")
	provider := &models.SSOProvider{
		// TODO handle Name, Description, Attribute Mapping
		SAMLProvider: nil,
		OIDCProvider: &models.OIDCProvider{
			Issuer:           config.Issuer,
			ClientId:         config.ClientID[0],
			AuthURL:          config.AuthURL,
			TokenURL:         config.TokenURL,
			UserInfoURL:      config.UserInfoURL,
			Secret:           config.Secret,
			RedirectURI:      config.RedirectURI,
			AttributeMapping: models.UserDataMapping{Keys: config.UserDataMapping},
		},
	}
	log.Println("24")

	// if params.MetadataURL != "" {
	// 	provider.SAMLProvider.MetadataURL = &params.MetadataURL
	// }

	// if params.NameIDFormat != "" {
	// 	provider.SAMLProvider.NameIDFormat = &params.NameIDFormat
	// }

	// provider.SAMLProvider.AttributeMapping = params.AttributeMapping

	for _, domain := range params.Domains {
		existingProvider, err := models.FindSSOProviderByDomain(db, domain)
		if err != nil && !models.IsNotFoundError(err) {
			return err
		}
		if existingProvider != nil {
			return badRequestError(ErrorCodeSSODomainAlreadyExists, "SSO Domain '%s' is already assigned to an SSO identity provider (%s)", domain, existingProvider.ID.String())
		}

		provider.SSODomains = append(provider.SSODomains, models.SSODomain{
			Domain: domain,
		})
	}
	log.Println("25")

	if err := db.Transaction(func(tx *storage.Connection) error {

		if terr := tx.Eager().Create(provider); terr != nil {
			return terr
		}

		return tx.Eager().Load(provider)
	}); err != nil {
		return err
	}
	log.Println("26")

	return sendJSON(w, http.StatusCreated, provider)
}

// adminSSOProvidersGet returns an existing SAML Identity Provider in the system.
func (a *API) adminOIDCSSOProvidersGet(w http.ResponseWriter, r *http.Request) error {
	provider := getSSOProvider(r.Context())

	return sendJSON(w, http.StatusOK, provider)
}

// adminSSOProvidersUpdate updates a provider with the provided diff values.
// func (a *API) adminOIDCSSOProvidersUpdate(w http.ResponseWriter, r *http.Request) error {
// 	ctx := r.Context()
// 	db := a.db.WithContext(ctx)

// 	params := &CreateSSOProviderParams{}
// 	if err := retrieveRequestParams(r, params); err != nil {
// 		return err
// 	}

// 	if err := params.validate(true /* <- forUpdate */); err != nil {
// 		return err
// 	}

// 	modified := false
// 	updateSAMLProvider := false

// 	provider := getSSOProvider(ctx)

// 	if params.MetadataXML != "" || params.MetadataURL != "" {
// 		// metadata is being updated
// 		rawMetadata, metadata, err := params.metadata(ctx)
// 		if err != nil {
// 			return err
// 		}

// 		if provider.SAMLProvider.EntityID != metadata.EntityID {
// 			return badRequestError(ErrorCodeSAMLEntityIDMismatch, "SAML Metadata can be updated only if the EntityID matches for the provider; expected '%s' but got '%s'", provider.SAMLProvider.EntityID, metadata.EntityID)
// 		}

// 		if params.MetadataURL != "" {
// 			provider.SAMLProvider.MetadataURL = &params.MetadataURL
// 		}

// 		provider.SAMLProvider.MetadataXML = string(rawMetadata)
// 		updateSAMLProvider = true
// 		modified = true
// 	}

// 	// domains are being "updated" only when params.Domains is not nil, if
// 	// it was nil (but not `[]`) then the caller is expecting not to modify
// 	// the domains
// 	updateDomains := params.Domains != nil

// 	var createDomains, deleteDomains []models.SSODomain
// 	keepDomains := make(map[string]bool)

// 	for _, domain := range params.Domains {
// 		existingProvider, err := models.FindSSOProviderByDomain(db, domain)
// 		if err != nil && !models.IsNotFoundError(err) {
// 			return err
// 		}
// 		if existingProvider != nil {
// 			if existingProvider.ID == provider.ID {
// 				keepDomains[domain] = true
// 			} else {
// 				return badRequestError(ErrorCodeSSODomainAlreadyExists, "SSO domain '%s' already assigned to another provider (%s)", domain, existingProvider.ID.String())
// 			}
// 		} else {
// 			modified = true
// 			createDomains = append(createDomains, models.SSODomain{
// 				Domain:        domain,
// 				SSOProviderID: provider.ID,
// 			})
// 		}
// 	}

// 	if updateDomains {
// 		for i, domain := range provider.SSODomains {
// 			if !keepDomains[domain.Domain] {
// 				modified = true
// 				deleteDomains = append(deleteDomains, provider.SSODomains[i])
// 			}
// 		}
// 	}

// 	updateAttributeMapping := false
// 	if params.AttributeMapping.Keys != nil {
// 		updateAttributeMapping = !provider.SAMLProvider.AttributeMapping.Equal(&params.AttributeMapping)
// 		if updateAttributeMapping {
// 			modified = true
// 			provider.SAMLProvider.AttributeMapping = params.AttributeMapping
// 		}
// 	}

// 	nameIDFormat := ""
// 	if provider.SAMLProvider.NameIDFormat != nil {
// 		nameIDFormat = *provider.SAMLProvider.NameIDFormat
// 	}

// 	if params.NameIDFormat != nameIDFormat {
// 		modified = true

// 		if params.NameIDFormat == "" {
// 			provider.SAMLProvider.NameIDFormat = nil
// 		} else {
// 			provider.SAMLProvider.NameIDFormat = &params.NameIDFormat
// 		}
// 	}

// 	if modified {
// 		if err := db.Transaction(func(tx *storage.Connection) error {
// 			if terr := tx.Eager().Update(provider); terr != nil {
// 				return terr
// 			}

// 			if updateDomains {
// 				if terr := tx.Destroy(deleteDomains); terr != nil {
// 					return terr
// 				}

// 				if terr := tx.Eager().Create(createDomains); terr != nil {
// 					return terr
// 				}
// 			}

// 			if updateAttributeMapping || updateSAMLProvider {
// 				if terr := tx.Eager().Update(&provider.SAMLProvider); terr != nil {
// 					return terr
// 				}
// 			}

// 			return tx.Eager().Load(provider)
// 		}); err != nil {
// 			return unprocessableEntityError(ErrorCodeConflict, "Updating SSO provider failed, likely due to a conflict. Try again?").WithInternalError(err)
// 		}
// 	}

// 	return sendJSON(w, http.StatusOK, provider)
// }

// adminSSOProvidersDelete deletes a SAML identity provider.
func (a *API) adminOIDCSSOProvidersDelete(w http.ResponseWriter, r *http.Request) error {
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
