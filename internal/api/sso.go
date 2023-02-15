package api

import (
	"encoding/json"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/gofrs/uuid"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
	"github.com/supabase/gotrue/internal/utilities"
)

type SingleSignOnParams struct {
	ProviderID       uuid.UUID `json:"provider_id"`
	Domain           string    `json:"domain"`
	RedirectTo       string    `json:"redirect_to"`
	SkipHTTPRedirect *bool     `json:"skip_http_redirect"`
}

type SingleSignOnResponse struct {
	URL string `json:"url"`
}

func (p *SingleSignOnParams) validate() (bool, error) {
	hasProviderID := p.ProviderID != uuid.Nil
	hasDomain := p.Domain != ""

	if hasProviderID && hasDomain {
		return hasProviderID, badRequestError("Only one of provider_id or domain supported")
	} else if !hasProviderID && !hasDomain {
		return hasProviderID, badRequestError("A provider_id or domain needs to be provided")
	}

	return hasProviderID, nil
}

// SingleSignOn handles the single-sign-on flow for a provided SSO domain or provider.
func (a *API) SingleSignOn(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	body, err := getBodyBytes(r)
	if err != nil {
		return internalServerError("Unable to read request body").WithInternalError(err)
	}

	var params SingleSignOnParams

	if err := json.Unmarshal(body, &params); err != nil {
		return badRequestError("Unable to parse request body as JSON").WithInternalError(err)
	}

	hasProviderID := false

	if hasProviderID, err = params.validate(); err != nil {
		return err
	}

	var ssoProvider *models.SSOProvider

	if hasProviderID {
		ssoProvider, err = models.FindSSOProviderByID(db, params.ProviderID)
		if models.IsNotFoundError(err) {
			return notFoundError("No such SSO provider")
		} else if err != nil {
			return internalServerError("Unable to find SSO provider by ID").WithInternalError(err)
		}
	} else {
		ssoProvider, err = models.FindSSOProviderByDomain(db, params.Domain)
		if models.IsNotFoundError(err) {
			return notFoundError("No SSO provider assigned for this domain")
		} else if err != nil {
			return internalServerError("Unable to find SSO provider by domain").WithInternalError(err)
		}
	}

	entityDescriptor, err := ssoProvider.SAMLProvider.EntityDescriptor()
	if err != nil {
		return internalServerError("Error parsing SAML Metadata for SAML provider").WithInternalError(err)
	}

	// TODO: fetch new metadata if validUntil < time.Now()

	serviceProvider := a.getSAMLServiceProvider(entityDescriptor, false /* <- idpInitiated */)

	authnRequest, err := serviceProvider.MakeAuthenticationRequest(
		serviceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return internalServerError("Error creating SAML Authentication Request").WithInternalError(err)
	}

	relayState := models.SAMLRelayState{
		SSOProviderID: ssoProvider.ID,
		RequestID:     authnRequest.ID,
		FromIPAddress: utilities.GetIPAddress(r),
		RedirectTo:    params.RedirectTo,
	}

	if err := db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(&relayState); terr != nil {
			return internalServerError("Error creating SAML relay state from sign up").WithInternalError(err)
		}

		return nil
	}); err != nil {
		return err
	}

	ssoRedirectURL, err := authnRequest.Redirect(relayState.ID.String(), serviceProvider)
	if err != nil {
		return internalServerError("Error creating SAML authentication request redirect URL").WithInternalError(err)
	}

	skipHTTPRedirect := false

	if params.SkipHTTPRedirect != nil {
		skipHTTPRedirect = *params.SkipHTTPRedirect
	}

	if skipHTTPRedirect {
		return sendJSON(w, http.StatusOK, SingleSignOnResponse{
			URL: ssoRedirectURL.String(),
		})
	}

	http.Redirect(w, r, ssoRedirectURL.String(), http.StatusSeeOther)
	return nil
}
