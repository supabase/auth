package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/metering"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// EthParams contains the request body params for the eth endpoint, all values hex encoded
type EthParams struct {
	WalletAddress string `json:"wallet_address"`
	NonceId       string `json:"nonce_id"`
	Signature     string `json:"signature"`
}

func hashMessageWithKeccak256(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
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

	// TODO (HarryET): Validate nonce expiry time

	// Get the client's IP
	clientIP := strings.Split(r.RemoteAddr, ":")[0]

	// Validate the client's IP is the same as the one that created the nonce
	if !nonce.VerifyIp(clientIP) {
		return badRequestError("IP not the same as the IP this nonce was issued too")
	}

	// Convert the wallet address from params to an address struct
	walletAddress := common.HexToAddress(params.WalletAddress)

	// Decode the signature
	sig, err := hexutil.Decode(params.Signature)
	if err != nil {
		return badRequestError("Invalid Signature: Failed to decode, not valid hex")
	}

	// Check the nonce is correctly formatted
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if sig[64] != 27 && sig[64] != 28 {
		return badRequestError("Invalid Signature: Invalid formatting")
	}
	sig[64] -= 27

	// The nonce string that was built
	var nonceString string

	// Get Statement
	statement := config.External.Eth.Message

	// Check if statement was set
	if statement != "" {
		// Build the nonce string - with a statement - that is compliant with EIP-4361
		nonceString, err = nonce.BuildWithStatement(statement)
	} else {
		// Build the nonce string that is compliant with EIP-4361
		nonceString, err = nonce.Build()
	}
	msg := []byte(nonceString)

	// Use the signature and hashed nonce string to extract the public key
	pubKey, err := crypto.SigToPub(hashMessageWithKeccak256(msg), sig)
	if err != nil {
		return badRequestError("Invalid Signature: Failed to extract public key")
	}

	// Convert the public key to an address
	recoveredWalletAddress := crypto.PubkeyToAddress(*pubKey)

	// Check if the address from params is the same as the recovered address
	if walletAddress != recoveredWalletAddress {
		return badRequestError("Invalid Signature: Wallet address not the same as supplied address")
	}

	// Default Signin/Signup logic from `./signup.go`
	didUserExist := true

	aud := a.requestAud(ctx, r)
	user, uerr := models.FindUserByEthAddressAndAudience(a.db, instanceID, params.WalletAddress, aud)

	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	if models.IsNotFoundError(uerr) {
		uerr = a.db.Transaction(func(tx *storage.Connection) error {
			user, uerr = a.signupNewUser(ctx, tx, &SignupParams{
				EthAddress: params.WalletAddress,
				Provider:   "eth",
				Aud:        aud,
			})
			didUserExist = false

			if uerr = models.NewAuditLogEntry(tx, instanceID, user, models.UserSignedUpAction, nil); uerr != nil {
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
		return models.NewAuditLogEntry(tx, instanceID, user, models.NonceConsumed, nil)
	})

	if err != nil {
		return internalServerError("Failed to consume nonce").WithInternalError(err)
	}

	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if terr = models.NewAuditLogEntry(tx, instanceID, user, models.LoginAction, nil); terr != nil {
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
			if terr = a.setCookieToken(config, token.Token, useCookie == useSessionCookie, w); terr != nil {
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
