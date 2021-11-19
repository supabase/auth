package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// Web3Params contains the request body params for the web3 endpoint
type Web3Params struct {
	WalletAddress string `json:"wallet_address"`
	SignedNonce   string `json:"signed_nonce"`
}

func (a *API) Web3(w http.ResponseWriter, r *http.Request) error {
	params := &Web3Params{}
	body, err := ioutil.ReadAll(r.Body)
	jsonDecoder := json.NewDecoder(bytes.NewReader(body))
	if err = jsonDecoder.Decode(params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	return sendJSON(w, http.StatusOK, params)
}
