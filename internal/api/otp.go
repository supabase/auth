package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/sethvargo/go-password/password"
	"github.com/supabase/gotrue/internal/api/sms_provider"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

// OtpParams contains the request body params for the otp endpoint
type OtpParams struct {
	Email               string                 `json:"email"`
	Phone               string                 `json:"phone"`
	CreateUser          bool                   `json:"create_user"`
	Data                map[string]interface{} `json:"data"`
	Channel             string                 `json:"channel"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
	CodeChallenge       string                 `json:"code_challenge"`
}

// SmsParams contains the request body params for sms otp
type SmsParams struct {
	Phone               string                 `json:"phone"`
	Channel             string                 `json:"channel"`
	Data                map[string]interface{} `json:"data"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
	CodeChallenge       string                 `json:"code_challenge"`
}

func (p *OtpParams) Validate() error {
	if p.Email != "" && p.Phone != "" {
		return badRequestError("Only an email address or phone number should be provided")
	}
	if p.Email != "" && p.Channel != "" {
		return badRequestError("Channel should only be specified with Phone OTP")
	}
	if err := validatePKCEParams(p.CodeChallengeMethod, p.CodeChallenge); err != nil {
		return err
	}
	return nil
}

func (p *SmsParams) Validate(smsProvider string) error {
	if p.Phone != "" && !sms_provider.IsValidMessageChannel(p.Channel, smsProvider) {
		return badRequestError(InvalidChannelError)
	}

	var err error
	p.Phone, err = validatePhone(p.Phone)
	if err != nil {
		return err
	}

	return nil
}

// Otp returns the MagicLink or SmsOtp handler based on the request body params
func (a *API) Otp(w http.ResponseWriter, r *http.Request) error {
	params := &OtpParams{
		CreateUser: true,
	}
	if params.Data == nil {
		params.Data = make(map[string]interface{})
	}

	body, err := getBodyBytes(r)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read verification params: %v", err)
	}

	if err := params.Validate(); err != nil {
		return err
	}
	if params.Data == nil {
		params.Data = make(map[string]interface{})
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
	db := a.db.WithContext(ctx)
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
	// For backwards compatibility, we default to SMS if params Channel is not specified
	if params.Phone != "" && params.Channel == "" {
		params.Channel = sms_provider.SMSProvider
	}

	if err := params.Validate(config.Sms.Provider); err != nil {
		return err
	}

	var isNewUser bool
	aud := a.requestAud(ctx, r)
	user, err := models.FindUserByPhoneAndAudience(db, params.Phone, aud)
	if err != nil {
		if models.IsNotFoundError(err) {
			isNewUser = true
		} else {
			return internalServerError("Database error finding user").WithInternalError(err)
		}
	}
	if user != nil {
		isNewUser = !user.IsPhoneConfirmed()
	}
	if isNewUser {
		// User either doesn't exist or hasn't completed the signup process.
		// Sign them up with temporary password.
		password, err := password.Generate(64, 10, 0, false, true)
		if err != nil {
			internalServerError("error creating user").WithInternalError(err)
		}

		signUpParams := &SignupParams{
			Phone:    params.Phone,
			Password: password,
			Data:     params.Data,
			Channel:  params.Channel,
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
				Phone:   params.Phone,
				Channel: params.Channel,
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

	err = db.Transaction(func(tx *storage.Connection) error {
		if err := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", map[string]interface{}{
			"channel": params.Channel,
		}); err != nil {
			return err
		}
		smsProvider, terr := sms_provider.GetSmsProvider(*config)
		if terr != nil {
			return badRequestError("Error sending sms: %v", terr)
		}
		if err := a.sendPhoneConfirmation(ctx, tx, user, params.Phone, phoneConfirmationOtp, smsProvider, params.Channel); err != nil {
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
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	if !params.CreateUser {
		ctx := r.Context()
		aud := a.requestAud(ctx, r)
		var err error
		if params.Email != "" {
			params.Email, err = validateEmail(params.Email)
			if err != nil {
				return false, err
			}
			_, err = models.FindUserByEmailAndAudience(db, params.Email, aud)
		} else if params.Phone != "" {
			params.Phone, err = validatePhone(params.Phone)
			if err != nil {
				return false, err
			}
			_, err = models.FindUserByPhoneAndAudience(db, params.Phone, aud)
		}

		if err != nil && models.IsNotFoundError(err) {
			return false, nil
		}
	}
	return true, nil
}
