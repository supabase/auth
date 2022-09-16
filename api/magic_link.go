package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/sethvargo/go-password/password"
)

// MagicLinkParams holds the parameters for a magic link request
type MagicLinkParams struct {
	Email string                 `json:"email"`
	Data  map[string]interface{} `json:"metadata"`
}

// MagicLink sends a recovery email
func (a *API) MagicLink(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	if !config.External.Email.Enabled {
		return badRequestError("Email logins are disabled")
	}

	params := &MagicLinkParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	if params.Data == nil {
		params.Data = make(map[string]interface{})
	}

	if params.Email == "" {
		return unprocessableEntityError("Password recovery requires an email")
	}
	if err := a.validateEmail(ctx, params.Email); err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)
	user, err := models.FindUserByEmailAndAudience(db, params.Email, aud)
	if err != nil {
		if models.IsNotFoundError(err) {
			// User doesn't exist, sign them up with temporary password
			password, err := password.Generate(64, 10, 0, false, true)
			if err != nil {
				internalServerError("error creating user").WithInternalError(err)
			}

			signUpParams := &SignupParams{
				Email:    params.Email,
				Password: password,
				Data:     params.Data,
			}
			newBodyContent, err := json.Marshal(signUpParams)
			if err != nil {
				return badRequestError("Could not parse metadata: %v", err)
			}
			r.Body = io.NopCloser(strings.NewReader(string(newBodyContent)))
			r.ContentLength = int64(len(string(newBodyContent)))

			fakeResponse := &responseStub{}
			if config.Mailer.Autoconfirm {
				// signups are autoconfirmed, send magic link after signup
				if err := a.Signup(fakeResponse, r); err != nil {
					return err
				}
				newBodyContent := &SignupParams{
					Email: params.Email,
					Data:  params.Data,
				}
				metadata, err := json.Marshal(newBodyContent)
				if err != nil {
					return badRequestError("Could not parse metadata: %v", err)
				}
				r.Body = io.NopCloser(bytes.NewReader(metadata))
				return a.MagicLink(w, r)
			}
			// otherwise confirmation email already contains 'magic link'
			if err := a.Signup(fakeResponse, r); err != nil {
				return err
			}

			return sendJSON(w, http.StatusOK, make(map[string]string))
		}
		return internalServerError("Database error finding user").WithInternalError(err)
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
			return terr
		}

		mailer := a.Mailer(ctx)
		referrer := a.getReferrer(r)
		return a.sendMagicLink(tx, user, mailer, config.SMTP.MaxFrequency, referrer, config.Mailer.OtpLength)
	})
	if err != nil {
		if errors.Is(err, MaxFrequencyLimitError) {
			return tooManyRequestsError("For security purposes, you can only request this once every 60 seconds")
		}
		return internalServerError("Error sending magic link").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, make(map[string]string))
}

// responseStub only implement http responsewriter for ignoring
// incoming data from methods where it passed
type responseStub struct {
}

func (rw *responseStub) Header() http.Header {
	return http.Header{}
}

func (rw *responseStub) Write(data []byte) (int, error) {
	return 1, nil
}

func (rw *responseStub) WriteHeader(statusCode int) {
}
