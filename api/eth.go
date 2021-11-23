package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// EthParams contains the request body params for the eth endpoint
type EthParams struct {
	WalletAddress string `json:"wallet_address"`
	NonceId       string `json:"nonce_id"`
	Signature     string `json:"signature"`
}

func (a *API) Eth(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	if !config.External.Eth.Enabled {
		return badRequestError("Unsupported eth provider")
	}

	params := &EthParams{}
	body, err := ioutil.ReadAll(r.Body)
	jsonDecoder := json.NewDecoder(bytes.NewReader(body))
	if err = jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	nonce, err := models.GetNonceById(a.db, uuid.FromStringOrNil(params.NonceId))
	if err != nil {
		return badRequestError("Failed to find nonce: %v", err)
	}

	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if !nonce.VerifyIp(clientIP) {
		return badRequestError("IP not the same as the IP this nonce was issued too")
	}

	builtNonce, err := nonce.Build()
	if err != nil {
		return internalServerError("Failed to verify nonce")
	}
	nonceHash := crypto.Keccak256Hash([]byte(builtNonce))

	walletAddressBytes, err := hexutil.Decode(params.WalletAddress)
	if err != nil {
		return badRequestError("Failed to decode wallet address: %v", err)
	}

	signatureBytes, err := hexutil.Decode(params.Signature)
	if err != nil {
		return badRequestError("Failed to decode signature: %v", err)
	}

	publicKeySignatureBytes, err := crypto.Ecrecover(nonceHash.Bytes(), signatureBytes)
	if err != nil {
		return badRequestError("Failed to recover signature public key: %v", err)
	}

	matches := bytes.Equal(publicKeySignatureBytes, walletAddressBytes)
	if !matches {
		return badRequestError("Wallet address and signature public key didn't match")
	}

	signatureNoRecoverID := signatureBytes[:len(signatureBytes)-1]
	verified := crypto.VerifySignature(walletAddressBytes, nonceHash.Bytes(), signatureNoRecoverID)
	if !verified {
		return badRequestError("Invalid signature")
	}

	aud := a.requestAud(ctx, r)
	user, uerr := models.FindUserByWalletAddressAndAudience(a.db, instanceID, params.WalletAddress, aud)
	if uerr != nil {
		// if user does not exists, sign up the user
		if models.IsNotFoundError(uerr) {
			// TODO (HarryET): Signup User account
		}
		return internalServerError("Database error finding user").WithInternalError(uerr)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.NonceConsumed, nil); terr != nil {
			return terr
		}
		return nonce.Consume(tx)
	})

	if err != nil {
		return internalServerError("Failed to consume nonce").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, make(map[string]string))
}
