package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/sethvargo/go-password/password"
)

// Web3Params contains the request body params for the web3 endpoint
type Web3Params struct {
	WalletAddress string `json:"wallet_address"`
	Nonce         string `json:"nonce"`
	Signature     string `json:"signature"`
}

func (a *API) Web3(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)

	if !config.Web3.Enabled {
		return badRequestError("Unsupported web3 provider")
	}

	params := &Web3Params{}
	body, err := ioutil.ReadAll(r.Body)
	jsonDecoder := json.NewDecoder(bytes.NewReader(body))
	if err = jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	nonce, err := models.GetNonce(a.db, params.Nonce)
	if err != nil {
		return badRequestError("Failed to find nonce: %v", err)
	}

	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if !nonce.VerifyIp(clientIP) {
		return badRequestError("IP not the same as the IP this nonce was issued too")
	}

	nonceHash := crypto.Keccak256Hash([]byte(params.Nonce))

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
			password, err := password.Generate(64, 10, 0, false, true)
			if err != nil {
				internalServerError("error creating user").WithInternalError(err)
			}
			newBodyContent := `{"wallet_address":"` + params.WalletAddress + `","password":"` + password + `"}`
			r.Body = ioutil.NopCloser(strings.NewReader(newBodyContent))
			r.ContentLength = int64(len(newBodyContent))

			fakeResponse := &responseStub{}

			if err := a.Signup(fakeResponse, r); err != nil {
				return err
			}
			return sendJSON(w, http.StatusOK, make(map[string]string))
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
