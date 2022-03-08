package api

import (
	"encoding/json"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/models"

	"github.com/netlify/gotrue/storage"
)

// GetChallengeTokenParams are the parameters the Signup endpoint accepts
type GetChallengeTokenParams struct {
	Key       string `json:"key"`
	Algorithm string `json:"algorithm"`
}

// GetChallengeTokenResponse is the response struct from Signup endpoint
type GetChallengeTokenResponse struct {
	ChallengeToken string `json:"challenge_token"`
}

func (a *API) GetChallengeToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)

	params := &GetChallengeTokenParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read GetChallengeTokenParams params: %v", err)
	}

	err = models.VerifyKeyAndAlgorithm(params.Key, params.Algorithm)
	if err != nil {
		return unprocessableEntityError("Key verification failed: %v", err)
	}

	user, key, err := models.FindUserWithAsymmetrickey(a.db, params.Key)
	var challengeToken uuid.UUID

	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	aud := a.requestAud(ctx, r)
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		if user != nil && key != nil {
			challengeToken, terr = key.GetChallengeToken(tx)
			if terr != nil {
				return terr
			}
		} else if user == nil && key == nil {
			if config.DisableSignup {
				return forbiddenError("Signups not allowed for this instance")
			}

			user, terr = a.signupNewUser(ctx, tx, &SignupParams{
				Email:    "",
				Phone:    "",
				Password: "",
				Data:     nil,
				Provider: "AsymmetricKey",
				Aud:      aud,
			})

			if terr != nil {
				return terr
			}

			key, terr = models.NewAsymmetricKey(user.ID, params.Key, params.Algorithm, true)
			if terr != nil {
				return terr
			}

			if terr := tx.Create(key); terr != nil {
				return terr
			}

			challengeToken, terr = key.GetChallengeToken(tx)
			if terr != nil {
				return terr
			}
		} else {
			return internalServerError("Impossible case")
		}
		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, GetChallengeTokenResponse{ChallengeToken: challengeToken.String()})
}

// AsymmetricSignInParams are the parameters the Signin endpoint accepts
type AsymmetricSignInParams struct {
	Key                     string `json:"key"`
	ChallengeTokenSignature string `json:"challenge_token_signature"`
}

func (a *API) SignInWithAsymmetricKey(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.getConfig(ctx)
	cookie := r.Header.Get(useCookieHeader)

	params := &AsymmetricSignInParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read AsymmetricSignInParams params: %v", err)
	}

	user, key, err := models.FindUserWithAsymmetrickey(a.db, params.Key)
	if err != nil && models.IsNotFoundError(err) {
		return unauthorizedError("Unauthorized")
	}
	if err != nil && !models.IsNotFoundError(err) {
		return internalServerError("Database error finding key").WithInternalError(err)
	}

	if key.IsChallengeTokenExpired() {
		return unprocessableEntityError("Key challenge token has been expired")
	}

	if err = key.VerifySignature(params.ChallengeTokenSignature); err != nil {
		return unprocessableEntityError("Signature verification failed:%v", err)
	}

	var token *AccessTokenResponse
	err = a.db.Transaction(func(tx *storage.Connection) error {
		var terr error
		terr = tx.UpdateOnly(key, "challenge_passed")
		if terr != nil {
			return terr
		}

		token, terr = a.issueRefreshToken(ctx, tx, user)
		if terr != nil {
			return terr
		}

		if cookie != "" && config.Cookie.Duration > 0 {
			if terr = a.setCookieTokens(config, token, cookie == useSessionCookie, w); terr != nil {
				return internalServerError("Failed to set JWT cookie. %s", terr)
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	token.User = user
	return sendJSON(w, http.StatusOK, token)
}
