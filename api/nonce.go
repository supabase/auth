package api

import (
	"bytes"
	"encoding/json"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type NonceParams struct {
	WalletAddress string `json:"wallet_address"` // Hex Encoded
	ChainId       string `json:"chain_id"`
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
	if nonce != nil {
		nonce.UpdatedAt = time.Now().UTC()
		nonce.ExpiresAt = time.Now().UTC().Add(time.Minute * 2)
		if err = a.db.UpdateOnly(nonce, "updated_at", "expires_at"); err != nil {
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
