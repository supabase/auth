package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	siwe "github.com/spruceid/siwe-go"
)

type NonceParams struct {
	WalletAddress string `json:"wallet_address"` // Hex Encoded
	ChainId       int    `json:"chain_id"`
	Url           string `json:"url"` // Hex Encoded
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

	// Get client's ip
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	// TODO (HarryET): Fetch nonce with same IP & wallet address that is not expired so that less nonces are created

	// Get Statement
	statement := config.External.Eth.Message

	messageOptions := siwe.InitMessageOptions(map[string]interface{}{
		"statement":      statement,
		"issuedAt":       time.Now().UTC(),
		"nonce":          siwe.GenerateNonce(),
		"chainId":        params.ChainId,
		"expirationTime": time.Now().UTC().Add(time.Minute * 5),
	})
	uri, err := url.Parse(params.Url)
	if err != nil {
		// TODO (HarryET): Handle or return error
	}
	message := siwe.InitMessage(uri.Hostname(), params.WalletAddress, uri.String(), "1", *messageOptions)

	// Create new nonce
	nonce, err := models.NewNonce(instanceID, params.ChainId, params.Url, params.WalletAddress, "eip155", clientIP)
	if err != nil || nonce == nil {
		return internalServerError("Failed to generate nonce")
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
		Nonce: message.PrepareMessage(),
	})
}

func (a *API) NonceById(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)

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
	var builtNonce string

	// Get Statement
	statement := config.External.Eth.Message

	// Check if statement was set
	if statement != "" {
		// Build the nonce string - with a statement - that is compliant with EIP-4361
		builtNonce, err = nonce.BuildWithStatement(statement)
	} else {
		// Build the nonce string that is compliant with EIP-4361
		builtNonce, err = nonce.Build()
	}

	if err != nil {
		return internalServerError("Failed to build nonce")
	}

	// TODO (HarryET): Consider checking IP?

	// Return the nonce's id and the build string
	// TODO (HarryET): Consider just returning text?
	return sendJSON(w, http.StatusCreated, &NonceResponse{
		Id:    nonce.ID.String(),
		Nonce: builtNonce,
	})
}
