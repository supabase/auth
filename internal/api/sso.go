package api

import (
	"net/http"
	"net/url"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
)

type SingleSignOnParams struct {
	ProviderID          uuid.UUID `json:"provider_id"`
	Domain              string    `json:"domain"`
	RedirectTo          string    `json:"redirect_to"`
	SkipHTTPRedirect    *bool     `json:"skip_http_redirect"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
}

type SingleSignOnResponse struct {
	URL string `json:"url"`
}

func (p *SingleSignOnParams) validate() (bool, error) {
	hasProviderID := p.ProviderID != uuid.Nil
	hasDomain := p.Domain != ""

	if hasProviderID && hasDomain {
		return hasProviderID, badRequestError(ErrorCodeValidationFailed, "Only one of provider_id or domain supported")
	} else if !hasProviderID && !hasDomain {
		return hasProviderID, badRequestError(ErrorCodeValidationFailed, "A provider_id or domain needs to be provided")
	}

	return hasProviderID, nil
}

// SingleSignOn handles the single-sign-on flow for a provided SSO domain or provider.
func (a *API) SingleSignOn(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	params := &SingleSignOnParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	var err error
	hasProviderID := false

	if hasProviderID, err = params.validate(); err != nil {
		return err
	}
	codeChallengeMethod := params.CodeChallengeMethod
	codeChallenge := params.CodeChallenge

	if err := validatePKCEParams(codeChallengeMethod, codeChallenge); err != nil {
		return err
	}

	var ssoProvider *models.SSOProvider

	if hasProviderID {
		ssoProvider, err = models.FindSSOProviderByID(db, params.ProviderID)
		if models.IsNotFoundError(err) {
			return notFoundError(ErrorCodeSSOProviderNotFound, "No such SSO provider")
		} else if err != nil {
			return internalServerError("Unable to find SSO provider by ID").WithInternalError(err)
		}
	} else {
		ssoProvider, err = models.FindSSOProviderByDomain(db, params.Domain)
		if models.IsNotFoundError(err) {
			return notFoundError(ErrorCodeSSOProviderNotFound, "No SSO provider assigned for this domain")
		} else if err != nil {
			return internalServerError("Unable to find SSO provider by domain").WithInternalError(err)
		}
	}

	var authMethod models.AuthenticationMethod
	var providerType string
	// providerType, authMethod := "", models.AuthenticationMethod
	if ssoProvider.OIDCProvider == nil || ssoProvider.OIDCProvider.ClientId == "" {
		providerType, authMethod = models.SSOSAML.String(), models.SSOSAML
	} else {
		providerType, authMethod = models.SSOOIDC.String(), models.SSOOIDC
	}

	flowType := getFlowFromChallenge(params.CodeChallenge)
	var flowStateID *uuid.UUID
	flowStateID = nil
	if isPKCEFlow(flowType) {
		flowState, err := generateFlowState(db, providerType, authMethod, codeChallengeMethod, codeChallenge, nil)
		if err != nil {
			return err
		}
		flowStateID = &flowState.ID
	}

	var ssoRedirectURL *url.URL
	if authMethod == models.SSOSAML {
		ssoRedirectURL, err = GenerateRedirectWithSAML(a, db, ssoProvider, flowStateID, params)
		if err != nil {
			return internalServerError("Error creating SAML authentication request redirect URL").WithInternalError(err)
		}
	} else if authMethod == models.SSOOIDC {
		ssoRedirectURL, err = GenerateRedirectWithOIDC(a, db, ssoProvider, flowStateID, params)
		if err != nil {
			return internalServerError("Error creating OIDC authentication request redirect URL").WithInternalError(err)
		}
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
