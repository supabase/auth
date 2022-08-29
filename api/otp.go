package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/netlify/gotrue/api/sms_provider"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/sethvargo/go-password/password"
)

// OtpParams contains the request body params for the otp endpoint
type OtpParams struct {
	Email      string                 `json:"email"`
	Phone      string                 `json:"phone"`
	CreateUser bool                   `json:"create_user"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// SmsParams contains the request body params for sms otp
type SmsParams struct {
	Phone    string                 `json:"phone"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Otp returns the MagicLink or SmsOtp handler based on the request body params
func (a *API) Otp(w http.ResponseWriter, r *http.Request) error {
	params := &OtpParams{
		CreateUser: true,
	}
	if params.Metadata == nil {
		params.Metadata = make(map[string]interface{})
	}

	body, err := getBodyBytes(r)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}
	if params.Email != "" && params.Phone != "" {
		return badRequestError("Only an email address or phone number should be provided")
	}

	if ok, err := a.shouldCreateUser(r, params); !ok {
		return badRequestError("Signups not allowed for otp")
	} else if err != nil {
		return err
	}

	if params.Email != "" {
		return a.MagicLink(w, r)
	} else if params.Phone != "" {
		return a.SmsOtp(w, r)
	}

	return otpError("unsupported_otp_type", "")
}

// SmsOtp sends the user an otp via sms
func (a *API) SmsOtp(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	config := a.config

	if !config.External.Phone.Enabled {
		return badRequestError("Unsupported phone provider")
	}
	var err error

	params := &SmsParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read sms otp params: %v", err)
	}
	if params.Metadata == nil {
		params.Metadata = make(map[string]interface{})
	}

	params.Phone, err = a.validatePhone(params.Phone)
	if err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)

	user, uerr := models.FindUserByPhoneAndAudience(a.db, params.Phone, aud)
	if uerr != nil {
		// if user does not exists, sign up the user
		if models.IsNotFoundError(uerr) {
			password, err := password.Generate(64, 10, 0, false, true)
			if err != nil {
				internalServerError("error creating user").WithInternalError(err)
			}

			signUpParams := &SignupParams{
				Phone:    params.Phone,
				Password: password,
				Data:     params.Metadata,
			}
			newBodyContent, err := json.Marshal(signUpParams)
			if err != nil {
				return badRequestError("Could not parse metadata: %v", err)
			}
			r.Body = io.NopCloser(bytes.NewReader(newBodyContent))

			fakeResponse := &responseStub{}

			if config.Sms.Autoconfirm {
				// signups are autoconfirmed, send otp after signup
				if err := a.Signup(fakeResponse, r); err != nil {
					return err
				}

				signUpParams := &SignupParams{
					Phone: params.Phone,
				}
				newBodyContent, err := json.Marshal(signUpParams)
				if err != nil {
					return badRequestError("Could not parse metadata: %v", err)
				}
				r.Body = io.NopCloser(bytes.NewReader(newBodyContent))
				return a.SmsOtp(w, r)
			}

			if err := a.Signup(fakeResponse, r); err != nil {
				return err
			}
			return sendJSON(w, http.StatusOK, make(map[string]string))
		}
		return internalServerError("Database error finding user").WithInternalError(uerr)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if err := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); err != nil {
			return err
		}
		smsProvider, terr := sms_provider.GetSmsProvider(*config)
		if terr != nil {
			return badRequestError("Error sending sms: %v", terr)
		}
		if err := a.sendPhoneConfirmation(ctx, tx, user, params.Phone, phoneConfirmationOtp, smsProvider); err != nil {
			return badRequestError("Error sending sms otp: %v", err)
		}
		return nil
	})

	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, make(map[string]string))
}

func (a *API) shouldCreateUser(r *http.Request, params *OtpParams) (bool, error) {
	if !params.CreateUser {
		ctx := r.Context()
		aud := a.requestAud(ctx, r)
		var err error
		if params.Email != "" {
			if err := a.validateEmail(ctx, params.Email); err != nil {
				return false, err
			}
			_, err = models.FindUserByEmailAndAudience(a.db, params.Email, aud)
		} else if params.Phone != "" {
			params.Phone, err = a.validatePhone(params.Phone)
			if err != nil {
				return false, err
			}
			_, err = models.FindUserByPhoneAndAudience(a.db, params.Phone, aud)
		}

		if err != nil && models.IsNotFoundError(err) {
			return false, nil
		}
	}
	return true, nil
}
