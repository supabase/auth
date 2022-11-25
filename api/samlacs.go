package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/fatih/structs"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/api/provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/observability"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/utilities"
)

func (a *API) samlDestroyRelayState(ctx context.Context, relayState *models.SAMLRelayState) error {
	db := a.db.WithContext(ctx)

	// It's OK to destroy the RelayState, as a user will
	// likely initiate a completely new login flow, instead
	// of reusing the same one.

	return db.Transaction(func(tx *storage.Connection) error {
		return tx.Destroy(relayState)
	})
}

// SAMLACS implements the main Assertion Consumer Service endpoint behavior.
func (a *API) SAMLACS(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	db := a.db.WithContext(ctx)
	config := a.config
	log := observability.GetLogEntry(r)

	relayStateValue := r.FormValue("RelayState")
	relayStateUUID := uuid.FromStringOrNil(relayStateValue)
	relayStateURL, _ := url.ParseRequestURI(relayStateValue)

	entityId := ""
	initiatedBy := ""
	redirectTo := ""
	var requestIds []string

	if relayStateUUID != uuid.Nil {
		// relay state is a valid UUID, therefore this is likely a SP initiated flow

		relayState, err := models.FindSAMLRelayStateByID(db, relayStateUUID)
		if models.IsNotFoundError(err) {
			return badRequestError("SAML RelayState does not exist, try logging in again?")
		} else if err != nil {
			return err
		}

		if time.Since(relayState.CreatedAt) >= a.config.SAML.RelayStateValidityPeriod {
			if err := a.samlDestroyRelayState(ctx, relayState); err != nil {
				return internalServerError("SAML RelayState has expired and destroying it failed. Try logging in again?").WithInternalError(err)
			}

			return badRequestError("SAML RelayState has expired. Try loggin in again?")
		}

		if relayState.FromIPAddress != utilities.GetIPAddress(r) {
			if err := a.samlDestroyRelayState(ctx, relayState); err != nil {
				return internalServerError("SAML RelayState comes from another IP address and destroying it failed. Try logging in again?").WithInternalError(err)
			}

			return badRequestError("SAML RelayState comes from another IP address, try logging in again?")
		}

		// TODO: add abuse detection to bind the RelayState UUID with a
		// HTTP-Only cookie

		ssoProvider, err := models.FindSSOProviderByID(db, relayState.SSOProviderID)
		if err != nil {
			return internalServerError("Unable to find SSO Provider from SAML RelayState")
		}

		initiatedBy = "sp"
		entityId = ssoProvider.SAMLProvider.EntityID
		redirectTo = relayState.RedirectTo
		requestIds = append(requestIds, relayState.RequestID)

		if err := a.samlDestroyRelayState(ctx, relayState); err != nil {
			return err
		}
	} else if relayStateValue == "" || relayStateURL != nil {
		// RelayState may be a URL in which case it's the URL where the
		// IdP is telling us to redirect the user to

		if r.FormValue("SAMLart") != "" {
			// SAML Artifact responses are possible only when
			// RelayState can be used to identify the Identity
			// Provider.
			return badRequestError("SAML Artifact response can only be used with SP initiated flow")
		}

		samlResponse := r.FormValue("SAMLResponse")
		if samlResponse == "" {
			return badRequestError("SAMLResponse is missing")
		}

		responseXML, err := base64.StdEncoding.DecodeString(samlResponse)
		if err != nil {
			return badRequestError("SAMLResponse is not a valid Base64 string")
		}

		var peekResponse saml.Response
		err = xml.Unmarshal(responseXML, &peekResponse)
		if err != nil {
			return badRequestError("SAMLResponse is not a valid XML SAML assertion")
		}

		initiatedBy = "idp"
		entityId = peekResponse.Issuer.Value
		redirectTo = relayStateValue
	} else {
		// RelayState can't be identified, so SAML flow can't continue
		return badRequestError("SAML RelayState is not a valid UUID or URL")
	}

	ssoProvider, err := models.FindSAMLProviderByEntityID(db, entityId)
	if models.IsNotFoundError(err) {
		return badRequestError("A SAML connection has not been established with this Identity Provider")
	} else if err != nil {
		return err
	}

	idpMetadata, err := ssoProvider.SAMLProvider.EntityDescriptor()
	if err != nil {
		return err
	}

	if ssoProvider.SAMLProvider.MetadataURL == nil {
		if !idpMetadata.ValidUntil.IsZero() && time.Until(idpMetadata.ValidUntil) <= (30*24*60)*time.Second {
			logentry := log.WithField("sso_provider_id", ssoProvider.ID.String())
			logentry = logentry.WithField("expires_in", time.Until(idpMetadata.ValidUntil).String())
			logentry = logentry.WithField("valid_until", idpMetadata.ValidUntil)
			logentry = logentry.WithField("saml_entity_id", ssoProvider.SAMLProvider.EntityID)

			logentry.Warn("SAML Metadata for identity provider will expire soon! Update its metadata_xml!")
		}
	}

	// TODO: fetch new metadata if possible when validUntil < time.Now() or cacheDuration

	serviceProvider := a.getSAMLServiceProvider(idpMetadata, initiatedBy == "idp")
	spAssertion, err := serviceProvider.ParseResponse(r, requestIds)
	if err != nil {
		if ire, ok := err.(*saml.InvalidResponseError); ok {
			return badRequestError("SAML Assertion is not valid").WithInternalError(ire.PrivateErr)
		}

		return badRequestError("SAML Assertion is not valid").WithInternalError(err)
	}

	assertion := SAMLAssertion{
		spAssertion,
	}

	userID := assertion.UserID()
	if userID == "" {
		return badRequestError("SAML Assertion did not contain a persistent Subject Identifier attribute or Subject NameID uniquely identifying this user")
	}

	claims := assertion.Process(ssoProvider.SAMLProvider.AttributeMapping)

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		// mapping does not identify the email attribute, try to figure it out
		email = assertion.Email()
	}

	if email == "" {
		return badRequestError("SAML Assertion does not contain an email address")
	} else {
		claims["email"] = email
	}

	jsonClaims, err := json.Marshal(claims)
	if err != nil {
		return internalServerError("Mapped claims from provider could not be serialized into JSON").WithInternalError(err)
	}

	providerClaims := &provider.Claims{}
	if err := json.Unmarshal(jsonClaims, providerClaims); err != nil {
		return internalServerError("Mapped claims from provider could not be deserialized from JSON").WithInternalError(err)
	}

	providerClaims.Subject = userID
	providerClaims.Issuer = ssoProvider.SAMLProvider.EntityID
	providerClaims.Email = email
	providerClaims.EmailVerified = true

	providerClaimsMap := structs.Map(providerClaims)

	// remove all of the parsed claims, so that the rest can go into CustomClaims
	for key := range providerClaimsMap {
		delete(claims, key)
	}

	providerClaims.CustomClaims = claims

	var userProvidedData provider.UserProvidedData

	userProvidedData.Emails = append(userProvidedData.Emails, provider.Email{
		Email:    email,
		Verified: true,
		Primary:  true,
	})

	// userProvidedData.Provider.Type = "saml"
	// userProvidedData.Provider.ID = ssoProvider.ID.String()
	// userProvidedData.Provider.SAMLEntityID = ssoProvider.SAMLProvider.EntityID
	// userProvidedData.Provider.SAMLInitiatedBy = initiatedBy

	userProvidedData.Metadata = providerClaims

	// TODO: below
	// refreshTokenParams.SSOProviderID = ssoProvider.ID
	// refreshTokenParams.InitiatedByProvider = initiatedBy == "idp"
	// refreshTokenParams.NotBefore = assertion.NotBefore()
	// refreshTokenParams.NotAfter = assertion.NotAfter()

	notAfter := assertion.NotAfter()

	var grantParams models.GrantParams

	if !notAfter.IsZero() {
		grantParams.SessionNotAfter = &notAfter
	}

	var token *AccessTokenResponse

	if err := db.Transaction(func(tx *storage.Connection) error {
		var terr error
		var user *models.User

		// accounts potentially created via SAML can contain non-unique email addresses in the auth.users table
		if user, terr = a.createAccountFromExternalIdentity(tx, r, &userProvidedData, "sso:"+ssoProvider.ID.String()); terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user, models.SSOSAML, grantParams)

		if terr != nil {
			return internalServerError("Unable to issue refresh token from SAML Assertion").WithInternalError(terr)
		}

		return nil
	}); err != nil {
		return err
	}

	if err := a.setCookieTokens(config, token, false, w); err != nil {
		return internalServerError("Failed to set JWT cookie").WithInternalError(err)
	}

	if !isRedirectURLValid(config, redirectTo) {
		redirectTo = config.SiteURL
	}

	http.Redirect(w, r, token.AsRedirectURL(redirectTo, url.Values{}), http.StatusFound)

	return nil
}
