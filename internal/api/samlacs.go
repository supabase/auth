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
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
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

func IsSAMLMetadataStale(idpMetadata *saml.EntityDescriptor, samlProvider models.SAMLProvider) bool {
	now := time.Now()

	hasValidityExpired := !idpMetadata.ValidUntil.IsZero() && now.After(idpMetadata.ValidUntil)
	hasCacheDurationExceeded := idpMetadata.CacheDuration != 0 && now.After(samlProvider.UpdatedAt.Add(idpMetadata.CacheDuration))

	// if metadata XML does not publish validity or caching information, update once in 24 hours
	needsForceUpdate := idpMetadata.ValidUntil.IsZero() && idpMetadata.CacheDuration == 0 && now.After(samlProvider.UpdatedAt.Add(24*time.Hour))

	return hasValidityExpired || hasCacheDurationExceeded || needsForceUpdate
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

	var flowState *models.FlowState
	flowState = nil
	if relayStateUUID != uuid.Nil {
		// relay state is a valid UUID, therefore this is likely a SP initiated flow

		relayState, err := models.FindSAMLRelayStateByID(db, relayStateUUID)
		if models.IsNotFoundError(err) {
			return notFoundError(ErrorCodeSAMLRelayStateNotFound, "SAML RelayState does not exist, try logging in again?")
		} else if err != nil {
			return err
		}

		if time.Since(relayState.CreatedAt) >= a.config.SAML.RelayStateValidityPeriod {
			if err := a.samlDestroyRelayState(ctx, relayState); err != nil {
				return internalServerError("SAML RelayState has expired and destroying it failed. Try logging in again?").WithInternalError(err)
			}

			return unprocessableEntityError(ErrorCodeSAMLRelayStateExpired, "SAML RelayState has expired. Try logging in again?")
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
		if relayState.FlowState != nil {
			flowState = relayState.FlowState
		}

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
			return badRequestError(ErrorCodeValidationFailed, "SAML Artifact response can only be used with SP initiated flow")
		}

		samlResponse := r.FormValue("SAMLResponse")
		if samlResponse == "" {
			return badRequestError(ErrorCodeValidationFailed, "SAMLResponse is missing")
		}

		responseXML, err := base64.StdEncoding.DecodeString(samlResponse)
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "SAMLResponse is not a valid Base64 string")
		}

		var peekResponse saml.Response
		err = xml.Unmarshal(responseXML, &peekResponse)
		if err != nil {
			return badRequestError(ErrorCodeValidationFailed, "SAMLResponse is not a valid XML SAML assertion").WithInternalError(err)
		}

		initiatedBy = "idp"
		entityId = peekResponse.Issuer.Value
		redirectTo = relayStateValue
	} else {
		// RelayState can't be identified, so SAML flow can't continue
		return badRequestError(ErrorCodeValidationFailed, "SAML RelayState is not a valid UUID or URL")
	}

	ssoProvider, err := models.FindSAMLProviderByEntityID(db, entityId)
	if models.IsNotFoundError(err) {
		return notFoundError(ErrorCodeSAMLIdPNotFound, "A SAML connection has not been established with this Identity Provider")
	} else if err != nil {
		return err
	}

	idpMetadata, err := ssoProvider.SAMLProvider.EntityDescriptor()
	if err != nil {
		return err
	}

	samlMetadataModified := false

	if ssoProvider.SAMLProvider.MetadataURL == nil {
		if !idpMetadata.ValidUntil.IsZero() && time.Until(idpMetadata.ValidUntil) <= (30*24*60)*time.Second {
			logentry := log.WithField("sso_provider_id", ssoProvider.ID.String())
			logentry = logentry.WithField("expires_in", time.Until(idpMetadata.ValidUntil).String())
			logentry = logentry.WithField("valid_until", idpMetadata.ValidUntil)
			logentry = logentry.WithField("saml_entity_id", ssoProvider.SAMLProvider.EntityID)

			logentry.Warn("SAML Metadata for identity provider will expire soon! Update its metadata_xml!")
		}
	} else if *ssoProvider.SAMLProvider.MetadataURL != "" && IsSAMLMetadataStale(idpMetadata, ssoProvider.SAMLProvider) {
		rawMetadata, err := fetchSAMLMetadata(ctx, *ssoProvider.SAMLProvider.MetadataURL)
		if err != nil {
			// Fail silently but raise warning and continue with existing metadata
			logentry := log.WithField("sso_provider_id", ssoProvider.ID.String())
			logentry = logentry.WithField("expires_in", time.Until(idpMetadata.ValidUntil).String())
			logentry = logentry.WithField("valid_until", idpMetadata.ValidUntil)
			logentry = logentry.WithError(err)
			logentry.Warn("SAML Metadata could not be retrieved, continuing with existing metadata")
		} else {
			ssoProvider.SAMLProvider.MetadataXML = string(rawMetadata)
			samlMetadataModified = true
		}
	}

	serviceProvider := a.getSAMLServiceProvider(idpMetadata, initiatedBy == "idp")
	spAssertion, err := serviceProvider.ParseResponse(r, requestIds)
	if err != nil {
		if ire, ok := err.(*saml.InvalidResponseError); ok {
			return badRequestError(ErrorCodeValidationFailed, "SAML Assertion is not valid").WithInternalError(ire.PrivateErr)
		}

		return badRequestError(ErrorCodeValidationFailed, "SAML Assertion is not valid").WithInternalError(err)
	}

	assertion := SAMLAssertion{
		spAssertion,
	}

	userID := assertion.UserID()
	if userID == "" {
		return badRequestError(ErrorCodeSAMLAssertionNoUserID, "SAML Assertion did not contain a persistent Subject Identifier attribute or Subject NameID uniquely identifying this user")
	}

	claims := assertion.Process(ssoProvider.SAMLProvider.AttributeMapping)

	email, ok := claims["email"].(string)
	if !ok || email == "" {
		// mapping does not identify the email attribute, try to figure it out
		email = assertion.Email()
	}

	if email == "" {
		return badRequestError(ErrorCodeSAMLAssertionNoEmail, "SAML Assertion does not contain an email address")
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

	grantParams.FillGrantParams(r)

	if !notAfter.IsZero() {
		grantParams.SessionNotAfter = &notAfter
	}

	var token *AccessTokenResponse
	if samlMetadataModified {
		if err := db.UpdateColumns(&ssoProvider.SAMLProvider, "metadata_xml", "updated_at"); err != nil {
			return err
		}
	}

	if err := db.Transaction(func(tx *storage.Connection) error {
		var terr error
		var user *models.User

		// accounts potentially created via SAML can contain non-unique email addresses in the auth.users table
		if user, terr = a.createAccountFromExternalIdentity(tx, r, &userProvidedData, "sso:"+ssoProvider.ID.String()); terr != nil {
			return terr
		}
		if flowState != nil {
			// This means that the callback is using PKCE
			flowState.UserID = &(user.ID)
			if terr := tx.Update(flowState); terr != nil {
				return terr
			}
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

	if !utilities.IsRedirectURLValid(config, redirectTo) {
		redirectTo = config.SiteURL
	}
	if flowState != nil {
		// This means that the callback is using PKCE
		// Set the flowState.AuthCode to the query param here
		redirectTo, err = a.prepPKCERedirectURL(redirectTo, flowState.AuthCode)
		if err != nil {
			return err
		}
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return nil

	}
	http.Redirect(w, r, token.AsRedirectURL(redirectTo, url.Values{}), http.StatusFound)

	return nil
}
