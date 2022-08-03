package api

import (
	"bytes"
	"encoding/json"
	"github.com/netlify/gotrue/api/crypto_provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type NonceParams struct {
	Provider string                             `json:"provider"`
	Options  crypto_provider.CryptoNonceOptions `json:"options"`
}

type NonceResponse struct {
	Id    string `json:"id"`
	Nonce string `json:"nonce"`
}

func (a *API) Nonce(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	// Read body into params
	params := &NonceParams{}
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

	if !provider.RequiresNonce() {
		return badRequestError("%s provider does not require a nonce for authentication", strings.ToLower(params.Provider))
	}

	nonce, err := models.GetNonceByProviderAndWalletAddress(a.db, instanceID, params.Provider, params.Options.WalletAddress)
	if err != nil {
		// Only return if the error isn't `NonceNotFoundError`
		if _, ok := err.(*models.NonceNotFoundError); !ok {
			return badRequestError("Failed to find nonce: %v", err)
		}
	}

	if nonce != nil {
		nonce.UpdatedAt = time.Now().UTC()
		nonce.ExpiresAt = time.Now().UTC().Add(time.Minute * 2)
		if err = a.db.UpdateOnly(nonce, "updated_at", "expires_at"); err != nil {
			return internalServerError("failed to refresh nonce")
		}
		message, err := provider.BuildNonce(nonce)

		if err != nil {
			return internalServerError(err.Error())
		}

		return sendJSON(w, http.StatusOK, &NonceResponse{
			Id:    nonce.ID.String(),
			Nonce: message,
		})
	}

	nonce, err = provider.GenerateNonce(r, instanceID, params.Options)
	if err != nil || nonce == nil {
		return internalServerError("Failed to generate nonce")
	}

	message, err := provider.BuildNonce(nonce)
	if err != nil {
		return internalServerError(err.Error())
	}

	// Create new transaction
	err = a.db.Transaction(func(tx *storage.Connection) error {
		// Save nonce in database
		if err := tx.Create(nonce); err != nil {
			// Return error
			return internalServerError("Failed to save nonce")
		}

		return nil
	})

	// If transaction returned error, return to user via HTTP Response
	if err != nil {
		return err
	}

	// Return the nonce's id and the build string
	return sendJSON(w, http.StatusCreated, &NonceResponse{
		Id:    nonce.ID.String(),
		Nonce: message,
	})
}
