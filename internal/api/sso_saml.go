package api

import (
	"net/url"

	"github.com/crewjam/saml"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func GenerateRedirectWithSAML(a *API, db *storage.Connection, ssoProvider *models.SSOProvider, flowStateID *uuid.UUID, params *SingleSignOnParams) (*url.URL, error) {
	entityDescriptor, err := ssoProvider.SAMLProvider.EntityDescriptor()
	if err != nil {
		return &url.URL{}, internalServerError("Error parsing SAML Metadata for SAML provider").WithInternalError(err)
	}

	serviceProvider := a.getSAMLServiceProvider(entityDescriptor, false /* <- idpInitiated */)

	authnRequest, err := serviceProvider.MakeAuthenticationRequest(
		serviceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return &url.URL{}, internalServerError("Error creating SAML Authentication Request").WithInternalError(err)
	}

	// Some IdPs do not support the use of the `persistent` NameID format,
	// and require a different format to be sent to work.
	if ssoProvider.SAMLProvider.NameIDFormat != nil {
		authnRequest.NameIDPolicy.Format = ssoProvider.SAMLProvider.NameIDFormat
	}

	relayState := models.SAMLRelayState{
		SSOProviderID: ssoProvider.ID,
		RequestID:     authnRequest.ID,
		RedirectTo:    params.RedirectTo,
		FlowStateID:   flowStateID,
	}

	if err := db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(&relayState); terr != nil {
			return internalServerError("Error creating SAML relay state from sign up").WithInternalError(err)
		}

		return nil
	}); err != nil {
		return &url.URL{}, err
	}

	ssoRedirectURL, err := authnRequest.Redirect(relayState.ID.String(), serviceProvider)

	return ssoRedirectURL, err
}
