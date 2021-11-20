package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
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

	if !config.Web3.Enabled {
		return badRequestError("Unsupported web3 provider")
	}

	params := &Web3Params{}
	body, err := ioutil.ReadAll(r.Body)
	jsonDecoder := json.NewDecoder(bytes.NewReader(body))
	if err = jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	// TODO (HarryET): Check if nonce was issued by GoTrue

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

	// TODO (HarryET): Get or create user

	return sendJSON(w, http.StatusOK, verified && matches)
}
