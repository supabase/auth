package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
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
func (a *API) getSAMLServiceProvider(identityProvider *saml.EntityDescriptor, idpInitiated bool) *saml.ServiceProvider {
	externalURL, err := url.ParseRequestURI(a.config.API.ExternalURL)
	if err != nil {
		// this should not fail as a.config should have been validated using #Validate()
		panic(err)
	}

	// TODO: figure out idpInitiated properties for higher security

	provider := samlsp.DefaultServiceProvider(samlsp.Options{
		URL:         *externalURL,
		Key:         a.config.SAML.RSAPrivateKey,
		Certificate: a.config.SAML.Certificate,
		//SignRequest:       !idpInitiated,
		AllowIDPInitiated: true,
		IDPMetadata:       identityProvider,
	})

	return &provider
}

// SAMLMetadata serves GoTrue's SAML Service Provider metadata file.
func (a *API) SAMLMetadata(w http.ResponseWriter, r *http.Request) error {
	serviceProvider := a.getSAMLServiceProvider(nil /* <- identityProvider */, false /* <- idpInitiated */)

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

func (a *API) samlDestroyRelayState(relayState *models.SAMLRelayState) error {
	// It's OK to destroy the RelayState, as a user will
	// likely initiate a completely new login flow, instead
	// of reusing the same one.

	return a.db.Transaction(func(tx *storage.Connection) error {
		return tx.Destroy(relayState)
	})
}

// samlCallback implements the main Assertion Consumer Service endpoint behavior.
func (a *API) samlCallback(ctx context.Context, r *http.Request) (*provider.UserProvidedData, *models.GrantAuthenticatedConditions, error) {
	relayStateValue := r.FormValue("RelayState")
	relayStateUUID := uuid.FromStringOrNil(relayStateValue)
	relayStateURL, _ := url.ParseRequestURI(relayStateValue)

	entityId := ""
	initiatedBy := ""
	//redirectTo := ""
	var requestIds []string

	if relayStateUUID != uuid.Nil {
		// relay state is a valid UUID, therefore this is likely a SP initiated flow

		relayState, err := models.FindSAMLRelayStateByID(a.db, relayStateUUID)
		if models.IsNotFoundError(err) {
			return nil, nil, badRequestError("SAML RelayState does not exist, try logging in again?")
		} else if err != nil {
			return nil, nil, err
		}

		if time.Since(relayState.CreatedAt) >= a.config.SAML.RelayStateValidityPeriod {
			if err := a.samlDestroyRelayState(relayState); err != nil {
				return nil, nil, internalServerError("SAML RelayState has expired and destroying it failed. Try logging in again?").WithInternalError(err)
			}

			return nil, nil, badRequestError("SAML RelayState has expired. Try loggin in again?")
		}

		if relayState.FromIPAddress != getIPAddress(r) {
			if err := a.samlDestroyRelayState(relayState); err != nil {
				return nil, nil, internalServerError("SAML RelayState comes from another IP address and destroying it failed. Try logging in again?").WithInternalError(err)
			}

			return nil, nil, badRequestError("SAML RelayState comes from another IP address, try logging in again?")
		}

		// TODO: add abuse detection to bind the RelayState UUID with a
		// HTTP-Only cookie

		ssoProvider, err := models.FindSAMLProviderByID(a.db, relayState.SSOProviderID)
		if err != nil {
			return nil, nil, internalServerError("Unable to find SSO Provider from SAML RelayState")
		}

		initiatedBy = "sp"
		entityId = ssoProvider.SAMLProvider.EntityID
		//redirectTo = relayState.RedirectTo
		requestIds = append(requestIds, relayState.RequestID)

		if err := a.samlDestroyRelayState(relayState); err != nil {
			return nil, nil, err
		}
	} else if relayStateValue == "" || relayStateURL != nil {
		// RelayState may be a URL in which case it's the URL where the
		// IdP is telling us to redirect the user to

		if r.FormValue("SAMLart") != "" {
			// SAML Artifact responses are possible only when
			// RelayState can be used to identify the Identity
			// Provider.
			return nil, nil, badRequestError("SAML Artifact response can only be used with SP initiated flow")
		}

		samlResponse := r.FormValue("SAMLResponse")
		if samlResponse == "" {
			return nil, nil, badRequestError("SAMLResponse is missing")
		}

		responseXML, err := base64.StdEncoding.DecodeString(samlResponse)
		if err != nil {
			return nil, nil, badRequestError("SAMLResponse is not a valid Base64 string")
		}

		var peekResponse saml.Response
		err = xml.Unmarshal(responseXML, &peekResponse)
		if err != nil {
			return nil, nil, badRequestError("SAMLResponse is not a valid XML SAML assertion")
		}

		initiatedBy = "idp"
		entityId = peekResponse.Issuer.Value
		//redirectTo = relayStateValue
	} else {
		// RelayState can't be identified, so SAML flow can't continue
		return nil, nil, badRequestError("SAML RelayState is not a valid UUID or URL")
	}

	ssoProvider, err := models.FindSAMLProviderForEntityID(a.db, entityId)
	if models.IsNotFoundError(err) {
		return nil, nil, badRequestError("A SAML connection has not been established with this Identity Provider")
	} else if err != nil {
		return nil, nil, err
	}

	idpMetadata, err := ssoProvider.SAMLProvider.EntityDescriptor()
	if err != nil {
		return nil, nil, err
	}

	// TODO: fetch new metadata if possible when validUntil < time.Now()

	serviceProvider := a.getSAMLServiceProvider(idpMetadata, initiatedBy == "idp")
	spAssertion, err := serviceProvider.ParseResponse(r, requestIds)
	if err != nil {
		return nil, nil, badRequestError("SAML Assertion is not valid").WithInternalError(err)
	}

	assertion := SAMLAssertion{
		spAssertion,
	}

	userID := assertion.UserID()
	if userID == "" {
		return nil, nil, badRequestError("SAML Assertion did not contain a persistent Subject Identifier attribute or Subject NameID uniquely identifying this user")
	}

	claims := assertion.Process(ssoProvider.SAMLProvider.AttributeMapping)

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		email = assertion.Email()
	}

	if email == "" {
		return nil, nil, badRequestError("SAML Assertion did not contain a mapping for the email claim")
	} else {
		claims["email"] = email
	}

	jsonClaims, err := json.Marshal(claims)
	if err != nil {
		return nil, nil, internalServerError("Mapped claims from provider could not be serialized into JSON").WithInternalError(err)
	}

	providerClaims := &provider.Claims{}
	if err := json.Unmarshal(jsonClaims, providerClaims); err != nil {
		return nil, nil, internalServerError("Mapped claims from provider could not be deserialized from JSON").WithInternalError(err)
	}

	providerClaims.Subject = userID
	providerClaims.Issuer = ssoProvider.SAMLProvider.EntityID
	providerClaims.Email = email
	providerClaims.EmailVerified = true

	providerClaimsMap, err := providerClaims.ToMap()
	if err != nil {
		return nil, nil, internalServerError("Parsed provider claims could not be turned into a map").WithInternalError(err)
	}

	// remove all of the parsed claims, so that the rest can go into CustomClaims
	for key := range providerClaimsMap {
		delete(claims, key)
	}

	providerClaims.CustomClaims = claims

	var userProvidedData provider.UserProvidedData
	var cond models.GrantAuthenticatedConditions

	userProvidedData.Emails = append(userProvidedData.Emails, provider.Email{
		Email:    email,
		Verified: true,
		Primary:  true,
	})

	userProvidedData.Provider.Type = "saml"
	userProvidedData.Provider.ID = ssoProvider.ID.String()
	userProvidedData.Provider.SAMLEntityID = ssoProvider.SAMLProvider.EntityID
	userProvidedData.Provider.SAMLInitiatedBy = initiatedBy

	userProvidedData.Metadata = providerClaims

	cond.SSOProviderID = ssoProvider.ID
	cond.InitiatedByProvider = initiatedBy == "idp"
	cond.NotBefore = assertion.NotBefore()
	cond.NotAfter = assertion.NotAfter()

	return &userProvidedData, &cond, nil
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
	Name             string                      `json:"name"`
	Description      string                      `json:"description"`
	MetadataURL      string                      `json:"metadata_url"`
	MetadataXML      string                      `json:"metadata_xml"`
	Domains          []string                    `json:"domains"`
	AttributeMapping models.SAMLAttributeMapping `json:"attribute_mapping"`
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
	} else if !p.AttributeMapping.HasKey("email") {
		return badRequestError("email key must be definied in a SAML Attribute Mapping")
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

	return sendJSON(w, http.StatusOK, provider)
}

type SAMLAssertion struct {
	*saml.Assertion
}

const (
	SAMLSubjectIDAttributeName = "urn:oasis:names:tc:SAML:attribute:subject-id"
)

// Attribute returns the first matching attribute value in the attribute
// statements where name equals the official SAML attribute Name or
// FriendlyName. Returns nil if such an attribute can't be found.
func (a *SAMLAssertion) Attribute(name string) []saml.AttributeValue {
	var values []saml.AttributeValue

	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			// TODO: maybe this should be case-insentivite equality?
			if attr.Name == name || attr.FriendlyName == name {
				values = append(values, attr.Values...)
			}
		}
	}

	return values
}

// UserID returns the best choice for a persistent user identifier on the
// Identity Provider side. Don't assume the format of the string returned, as
// it's Identity Provider specific.
func (a *SAMLAssertion) UserID() string {
	// First we look up the SAMLSubjectIDAttributeName in the attribute
	// section of the assertion, as this is the preferred way to
	// persistently identify users in SAML 2.0.
	// See: https://docs.oasis-open.org/security/saml-subject-id-attr/v1.0/cs01/saml-subject-id-attr-v1.0-cs01.html#_Toc536097226
	values := a.Attribute(SAMLSubjectIDAttributeName)
	if len(values) > 0 {
		return values[0].Value
	}

	// Otherwise, fall back to the SubjectID value.
	subjectID, isPersistent := a.SubjectID()
	if !isPersistent {
		return ""
	}

	return subjectID
}

// SubjectID returns the user identifier in present in the Subject section of
// the SAML assertion. Note that this way of identifying the Subject is
// generally superseded by the SAMLSubjectIDAttributeName assertion attribute;
// tho must be present in all assertions. It can have a few formats, of which
// the most important are: saml.EmailAddressNameIDFormat (meaning the user ID
// is an email address), saml.PersistentNameIDFormat (the user ID is an opaque
// string that does not change with each assertion, e.g. UUID),
// saml.TransientNameIDFormat (the user ID changes with each assertion -- can't
// be used to identify a user). The boolean returned identifies if the user ID
// is persistent. If it's an email address, it's lowercased just in case.
func (a *SAMLAssertion) SubjectID() (string, bool) {
	if a.Subject == nil {
		return "", false
	}

	if a.Subject.NameID == nil {
		return "", false
	}

	if a.Subject.NameID.Value == "" {
		return "", false
	}

	if a.Subject.NameID.Format == string(saml.EmailAddressNameIDFormat) {
		return strings.ToLower(strings.TrimSpace(a.Subject.NameID.Value)), true
	}

	// all other NameID formats are regarded as persistent
	isPersistent := a.Subject.NameID.Format != string(saml.TransientNameIDFormat)

	return a.Subject.NameID.Value, isPersistent
}

// Email returns the best guess for an email address.
func (a *SAMLAssertion) Email() string {
	attributeNames := []string{
		"urn:oid:0.9.2342.19200300.100.1.3",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		"http://schemas.xmlsoap.org/claims/EmailAddress",
		"mail",
		"email",
	}

	for _, name := range attributeNames {
		for _, attr := range a.Attribute(name) {
			if attr.Value != "" {
				return attr.Value
			}
		}
	}

	if a.Subject.NameID.Format == string(saml.EmailAddressNameIDFormat) {
		return a.Subject.NameID.Value
	}

	return ""
}

// Process processes this assertion according to the SAMLAttributeMapping. Never returns nil.
func (a *SAMLAssertion) Process(mapping models.SAMLAttributeMapping) map[string]interface{} {
	ret := make(map[string]interface{})

	for key, mapper := range mapping.Keys {
		names := []string{mapper.Name}
		names = append(names, mapper.Names...)

		setKey := false

		for _, name := range names {
			for _, attr := range a.Attribute(name) {
				if attr.Value != "" {
					ret[key] = attr.Value
					setKey = true
					break
				}
			}

			if setKey {
				break
			}
		}

		if !setKey && mapper.Default != nil {
			ret[key] = mapper.Default
		}
	}

	return ret
}

func (a *SAMLAssertion) NotBefore() time.Time {
	if a.Conditions != nil && !a.Conditions.NotBefore.IsZero() {
		return a.Conditions.NotBefore.UTC()
	}

	return time.Time{}
}

func (a *SAMLAssertion) NotAfter() time.Time {
	if a.Conditions != nil && !a.Conditions.NotOnOrAfter.IsZero() {
		return a.Conditions.NotOnOrAfter.UTC()
	}

	return time.Time{}
}
