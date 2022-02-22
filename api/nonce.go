package api

import (
	"bytes"
	"encoding/json"
	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"io/ioutil"
	"net/http"
	"net/url"
)

type NonceParams struct {
	WalletAddress string `json:"wallet_address"` // Hex Encoded
	ChainId       int    `json:"chain_id"`
	Url           string `json:"url"`
}

type NonceResponse struct {
	Id    string `json:"id"`
	Nonce string `json:"nonce"`
}

func (a *API) Nonce(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	// Check if Ethereum login enabled in env
	if !config.External.Eth.Enabled {
		return badRequestError("Unsupported eth provider")
	}

	// Read body into params
	params := &NonceParams{}
	body, err := ioutil.ReadAll(r.Body)
	jsonDecoder := json.NewDecoder(bytes.NewReader(body))
	if err = jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	nonce, err := models.GetNonceByWalletAddress(a.db, params.WalletAddress)
	if !models.IsNotFoundError(err) {
		err = nonce.Refresh(a.db)
		if err != nil {
			return internalServerError("failed to refresh nonce")
		}
		message := nonce.ToMessage(a.config)
		return sendJSON(w, http.StatusOK, &NonceResponse{
			Id:    nonce.ID.String(),
			Nonce: message.PrepareMessage(),
		})
	}

	uri, err := url.Parse(params.Url)
	if err != nil {
		return badRequestError("Invalid url")
	}

	// Create new nonce
	nonce, err = models.NewNonce(instanceID, params.ChainId, uri.String(), uri.Hostname(), params.WalletAddress, "eip155")
	if err != nil || nonce == nil {
		return internalServerError("Failed to generate nonce")
	}

	message := nonce.ToMessage(a.config)

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
		Nonce: message.PrepareMessage(),
	})
}

func (a *API) NonceById(w http.ResponseWriter, r *http.Request) error {
	// Get nonce's id from the URL param and check if it is a UUID
	nonceId, err := uuid.FromString(chi.URLParam(r, "nonce_id"))
	if err != nil {
		// Throw a 400 - bad request - error if the nonce's id is not a UUID
		return badRequestError("nonce_id must be an UUID")
	}

	// Get the nonce by its ID
	nonce, err := models.GetNonceById(a.db, nonceId)
	if err != nil {
		// Check if the error is a not found error
		if models.IsNotFoundError(err) {
			return badRequestError("Invalid nonce_id")
		}
		return internalServerError("Failed to find nonce")
	}

	// The nonce string that was built
	message := nonce.ToMessage(a.config)

	if err != nil {
		return internalServerError("Failed to build nonce")
	}

	// Return the nonce's id and the build string
	return sendJSON(w, http.StatusOK, &NonceResponse{
		Id:    nonce.ID.String(),
		Nonce: message.PrepareMessage(),
	})
}
