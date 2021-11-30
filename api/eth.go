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

func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

func (a *API) Eth(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	instanceID := getInstanceID(ctx)
	useCookie := r.Header.Get(useCookieHeader)

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

	// TODO (HarryET): Validate nonce expiry time

	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if !nonce.VerifyIp(clientIP) {
		return badRequestError("IP not the same as the IP this nonce was issued too")
	}

	walletAddress := common.HexToAddress(params.WalletAddress)

	sig, err := hexutil.Decode(params.Signature)
	if err != nil {
		return badRequestError("Invalid Signature: Failed to decode, not valid hex")
	}

	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	if sig[64] != 27 && sig[64] != 28 {
		return badRequestError("Invalid Signature: Invalid formatting")
	}
	sig[64] -= 27

	statement := config.External.Eth.Message
	if statement == "" {
		statement = config.SiteURL
	}
	nonceString, err := nonce.Build(statement)
	msg := []byte(nonceString)
	pubKey, err := crypto.SigToPub(signHash(msg), sig)
	if err != nil {
		return badRequestError("Invalid Signature: Failed to extract public key")
	}

	recoveredWalletAddress := crypto.PubkeyToAddress(*pubKey)
	if walletAddress != recoveredWalletAddress {
		return badRequestError("Invalid Signature: Wallet address not the same as suplied address")
	}

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
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.NonceConsumed, nil); terr != nil {
			return terr
		}
		return nonce.Consume(tx)
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
