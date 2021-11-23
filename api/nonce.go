package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// NonceParams contains the request body params for the nonce endpoint
type NonceParams struct {
	WalletAddress string `json:"wallet_address"`
	ChainId       int    `json:"chain_id"`
	Url           string `json:"url"`
}

func (a *API) Nonce(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	if !config.External.Eth.Enabled {
		return badRequestError("Unsupported eth provider")
	}

	params := &NonceParams{}
	body, err := ioutil.ReadAll(r.Body)
	jsonDecoder := json.NewDecoder(bytes.NewReader(body))
	if err = jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	nonce, err := models.NewNonce(instanceID, params.ChainId, params.Url, params.WalletAddress, clientIP)
	if err != nil || nonce == nil {
		return internalServerError("Failed to generate nonce")
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if err := tx.Create(nonce); err != nil {
			return internalServerError("Failed to save nonce")
		}

		return nil
	})

	if err != nil {
		return err
	}

	builtNonce, err := nonce.Build()
	if err != nil {
		return internalServerError("Failed to build nonce")
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Add("X-Nonce-Id", nonce.ID.String())
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write([]byte(builtNonce))
	return err
}

func (a *API) NonceById(w http.ResponseWriter, r *http.Request) error {
	nonceId, err := uuid.FromString(chi.URLParam(r, "nonce_id"))
	if err != nil {
		return badRequestError("nonce_id must be an UUID")
	}

	nonce, err := models.GetNonceById(a.db, nonceId)
	if err != nil {
		if models.IsNotFoundError(err) {
			return badRequestError("Invalid nonce_id")
		}
		return internalServerError("Failed to find nonce")
	}

	builtNonce, err := nonce.Build()
	if err != nil {
		return internalServerError("Failed to build nonce")
	}

	// TODO (HarryET): Concider checking IP?

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Add("X-Nonce-Id", nonce.ID.String())
	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(builtNonce))
	return err
}
