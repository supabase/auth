package api

import (
	"bytes"
	"encoding/json"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"io/ioutil"
	"net/http"
)

// EthParams contains the request body params for the eth endpoint, all values hex encoded
type EthParams struct {
	NonceId   string `json:"nonce_id"`
	Signature string `json:"signature"`
}

func (a *API) Eth(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)
	useCookie := r.Header.Get(useCookieHeader)

	// Check if ethereum is enabled
	if !config.External.Eth.Enabled {
		return badRequestError("Unsupported eth provider")
	}

	// Get the params
	params := &EthParams{}
	body, err := ioutil.ReadAll(r.Body)
	jsonDecoder := json.NewDecoder(bytes.NewReader(body))
	if err = jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	// Get the nonce from the id in params
	nonce, err := models.GetNonceById(a.db, uuid.FromStringOrNil(params.NonceId))
	if err != nil {
		return badRequestError("Failed to find nonce: %v", err)
	}

	nonceMessage := nonce.ToMessage(a.config)
	_, err = nonceMessage.Verify(params.Signature)

	// Check if the address from params is the same as the recovered address
	if err != nil {
		return badRequestError(err.Error())
	}

	// Default Signin/Signup logic from `./signup.go`
	didUserExist := true

	aud := a.requestAud(ctx, r)
	user, uerr := models.FindUserByCryptoAddressAndAudience(a.db, instanceID, nonce.GetCaipAddress(), aud)

	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	if models.IsNotFoundError(uerr) {
		uerr = a.db.Transaction(func(tx *storage.Connection) error {
			user, uerr = a.signupNewUser(ctx, tx, &SignupParams{
				CryptoAddress: nonce.GetCaipAddress(),
				Provider:      "crypto",
				Aud:           aud,
			})
			didUserExist = false

			if uerr = user.Confirm(tx); uerr != nil {
				return uerr
			}

			if uerr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, "", nil); uerr != nil {
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
		return models.NewAuditLogEntry(tx, instanceID, user, models.NonceConsumed, "", nil)
	})

	if err != nil {
		return internalServerError("Failed to consume nonce").WithInternalError(err)
	}

	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, "", nil); terr != nil {
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
	metering.RecordLogin("eth", user.ID, instanceID)
	token.User = user

	status := http.StatusOK
	if !didUserExist {
		status = http.StatusCreated
	}
	return sendJSON(w, status, token)
}
