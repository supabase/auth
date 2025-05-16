package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/api/provider"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
	"github.com/supabase/auth/internal/utilities/siws"
)

type Web3GrantParams struct {
	Message   string `json:"message,omitempty"`
	Signature string `json:"signature,omitempty"`
	Chain     string `json:"chain,omitempty"`
}

func (a *API) Web3Grant(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	config := a.config

	if !config.External.Web3Solana.Enabled {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeWeb3ProviderDisabled, "Web3 provider is disabled")
	}

	params := &Web3GrantParams{}
	if err := retrieveRequestParams(r, params); err != nil {
		return err
	}

	if params.Chain != "solana" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeWeb3UnsupportedChain, "Unsupported chain")
	}

	return a.web3GrantSolana(ctx, w, r, params)
}

func (a *API) web3GrantSolana(ctx context.Context, w http.ResponseWriter, r *http.Request, params *Web3GrantParams) error {
	config := a.config
	db := a.db.WithContext(ctx)

	if len(params.Message) < 64 {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "message is too short")
	} else if len(params.Message) > 20*1024 {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "message must not exceed 20KB")
	}

	if len(params.Signature) != 86 && len(params.Signature) != 88 {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "signature must be 64 bytes encoded as base64 with or without padding")
	}

	base64URLSignature := strings.ReplaceAll(strings.ReplaceAll(strings.TrimRight(params.Signature, "="), "+", "-"), "/", "_")
	signatureBytes, err := base64.RawURLEncoding.DecodeString(base64URLSignature)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "signature does not contain valid base64 characters")
	}

	parsedMessage, err := siws.ParseMessage(params.Message)
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, err.Error())
	}

	if !parsedMessage.VerifySignature(signatureBytes) {
		return apierrors.NewOAuthError("invalid_grant", "Signature does not match address in message")
	}

	if parsedMessage.URI.Scheme != "https" && parsedMessage.URI.Hostname() != "localhost" {
		return apierrors.NewOAuthError("invalid_grant", "Signed Solana message is using URI which does not use HTTPS")
	}

	if !utilities.IsRedirectURLValid(config, parsedMessage.URI.String()) {
		return apierrors.NewOAuthError("invalid_grant", "Signed Solana message is using URI which is not allowed on this server, message was signed for another app")
	}

	if parsedMessage.URI.Hostname() != "localhost" && (parsedMessage.URI.Host != parsedMessage.Domain || !utilities.IsRedirectURLValid(config, "https://"+parsedMessage.Domain+"/")) {
		return apierrors.NewOAuthError("invalid_grant", "Signed Solana message is using a Domain that does not match the one in URI which is not allowed on this server")
	}

	now := a.Now()

	if !parsedMessage.NotBefore.IsZero() && now.Before(parsedMessage.NotBefore) {
		return apierrors.NewOAuthError("invalid_grant", "Signed Solana message becomes valid in the future")
	}

	if !parsedMessage.ExpirationTime.IsZero() && now.After(parsedMessage.ExpirationTime) {
		return apierrors.NewOAuthError("invalid_grant", "Signed Solana message is expired")
	}

	latestExpiryAt := parsedMessage.IssuedAt.Add(config.External.Web3Solana.MaximumValidityDuration)

	if now.After(latestExpiryAt) {
		return apierrors.NewOAuthError("invalid_grant", "Solana message was issued too long ago")
	}

	earliestIssuedAt := parsedMessage.IssuedAt.Add(-config.External.Web3Solana.MaximumValidityDuration)

	if now.Before(earliestIssuedAt) {
		return apierrors.NewOAuthError("invalid_grant", "Solana message was issued too far in the future")
	}

	providerId := strings.Join([]string{
		"web3",
		params.Chain,
		parsedMessage.Address,
	}, ":")

	userData := provider.UserProvidedData{
		Metadata: &provider.Claims{
			CustomClaims: map[string]interface{}{
				"address":   parsedMessage.Address,
				"chain":     params.Chain,
				"network":   parsedMessage.ChainID,
				"domain":    parsedMessage.Domain,
				"statement": parsedMessage.Statement,
			},
			Subject: providerId,
		},
		Emails: []provider.Email{},
	}

	var token *AccessTokenResponse
	var grantParams models.GrantParams
	grantParams.FillGrantParams(r)

	err = db.Transaction(func(tx *storage.Connection) error {
		user, terr := a.createAccountFromExternalIdentity(tx, r, &userData, "web3")
		if terr != nil {
			return terr
		}

		if terr := models.NewAuditLogEntry(r, tx, user, models.LoginAction, "", map[string]interface{}{
			"provider": "web3",
			"chain":    params.Chain,
			"network":  parsedMessage.ChainID,
			"address":  parsedMessage.Address,
			"domain":   parsedMessage.Domain,
			"uri":      parsedMessage.URI,
		}); terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(r, tx, user, models.Web3, grantParams)
		if terr != nil {
			return terr
		}

		return nil
	})

	if err != nil {
		switch err.(type) {
		case *storage.CommitWithError:
			return err
		case *HTTPError:
			return err
		default:
			return apierrors.NewOAuthError("server_error", "Internal Server Error").WithInternalError(err)
		}
	}

	return sendJSON(w, http.StatusOK, token)
}
