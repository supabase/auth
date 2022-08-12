package api

import (
	"bytes"
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/api/crypto_provider"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"io/ioutil"
	"net/http"
	"strings"
)

// CryptoParams contains the request body params for the eth endpoint, all values hex encoded
type CryptoParams struct {
	Provider  string  `json:"provider"`
	NonceId   *string `json:"nonce_id"`
	Signature *string `json:"signature"`
}

func (a *API) Crypto(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)
	useCookie := r.Header.Get(useCookieHeader)

	// Get the params
	params := &CryptoParams{}
	body, err := ioutil.ReadAll(r.Body)
	jsonDecoder := json.NewDecoder(bytes.NewReader(body))
	if err = jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	// Get the crypto provider
	provider, err := crypto_provider.GetCryptoProvider(config, params.Provider)
	if err != nil {
		return badRequestError(err.Error())
	}

	var nonce *models.Nonce = nil
	if provider.RequiresNonce() {
		if params.NonceId == nil {
			return badRequestError("Missing `nonce_id` which is required by %s provider", strings.ToLower(params.Provider))
		}

		if params.Signature == nil {
			return badRequestError("Missing `signature` which is required by %s provider", strings.ToLower(params.Provider))
		}

		// Get the nonce from the id in params
		nonce, err = models.GetNonceById(a.db, instanceID, uuid.FromStringOrNil(*params.NonceId))
		if err != nil {
			return badRequestError("Failed to find nonce: %v", err)
		}

		safe, err := provider.ValidateNonce(nonce, *params.Signature)
		if !safe {
			return badRequestError(err.Error())
		}

		if err != nil {
			return internalServerError(err.Error())
		}
	}

	didUserExist := true

	aud := a.requestAud(ctx, r)
	user, uerr := provider.FetchUser(a.db, instanceID, aud, nonce)

	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	if models.IsNotFoundError(uerr) {
		uerr = a.db.Transaction(func(tx *storage.Connection) error {
			accountInfo, uerr := provider.FetchAccountInformation(nonce)
			if uerr != nil {
				return uerr
			}

			user, uerr = a.signupNewUser(ctx, tx, &SignupParams{
				CryptoAddress:  accountInfo.Address,
				Provider:       "crypto",
				CryptoProvider: params.Provider,
				Aud:            aud,
			})
			didUserExist = false

			identity, terr := a.createNewIdentity(tx, user, params.Provider, map[string]interface{}{"sub": accountInfo.Address, "address": accountInfo.Address})
			if terr != nil {
				return terr
			}

			user.Identities = []models.Identity{*identity}

			if uerr = user.Confirm(tx); uerr != nil {
				return uerr
			}

			if uerr = models.NewAuditLogEntry(r, tx, instanceID, user, models.UserSignedUpAction, "", nil); uerr != nil {
				return uerr
			}
			if uerr = triggerEventHooks(ctx, tx, SignupEvent, user, instanceID, config); uerr != nil {
				return uerr
			}

			return uerr
		})

		if uerr != nil {
			return uerr
		}
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		// Consume the nonce
		if terr := nonce.Consume(tx); terr != nil {
			return terr
		}

		// Add audit log entry for consuming nonce
		return models.NewAuditLogEntry(r, tx, instanceID, user, models.NonceConsumed, "", nil)
	})

	if err != nil {
		return internalServerError("Failed to consume nonce").WithInternalError(err)
	}

	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(r, tx, instanceID, user, models.LoginAction, "", nil); terr != nil {
			return terr
		}
		if terr = triggerEventHooks(ctx, tx, LoginEvent, user, instanceID, config); terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user)
		if terr != nil {
			return terr
		}

		if useCookie != "" && config.Cookie.Duration > 0 {
			if terr = a.setCookieTokens(config, token, useCookie == useSessionCookie, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	metering.RecordLogin("crypto", user.ID, instanceID)
	token.User = user

	status := http.StatusOK
	if !didUserExist {
		status = http.StatusCreated
	}
	return sendJSON(w, status, token)
}
