package v0hooks

import (
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
)

type HookType string

const (
	PostgresHook HookType = "pg-functions"
)

// Hook Names
const (
	HookRejection = "reject"
)

type HTTPHookInput interface {
	IsHTTPHook()
}

type HookOutput interface {
	IsError() bool
	Error() string
	GetHookError() AuthHookError
}

// TODO(joel): Move this to phone package
type SMS struct {
	OTP     string `json:"otp,omitempty"`
	SMSType string `json:"sms_type,omitempty"`
}

// #nosec
const MinimumViableTokenSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "aud": {
      "type": ["string", "array"]
    },
    "exp": {
      "type": "integer"
    },
    "jti": {
      "type": "string"
    },
    "iat": {
      "type": "integer"
    },
    "iss": {
      "type": "string"
    },
    "nbf": {
      "type": "integer"
    },
    "sub": {
      "type": "string"
    },
    "email": {
      "type": "string"
    },
    "phone": {
      "type": "string"
    },
    "app_metadata": {
      "type": "object",
      "additionalProperties": true
    },
    "user_metadata": {
      "type": "object",
      "additionalProperties": true
    },
    "role": {
      "type": "string"
    },
    "aal": {
      "type": "string"
    },
    "amr": {
      "type": "array",
      "items": {
        "type": "object"
      }
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": ["aud", "exp", "iat", "sub", "email", "phone", "role", "aal", "session_id", "is_anonymous"]
}`

// AccessTokenClaims is a struct thats used for JWT claims
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Email                         string                 `json:"email"`
	Phone                         string                 `json:"phone"`
	AppMetaData                   map[string]interface{} `json:"app_metadata"`
	UserMetaData                  map[string]interface{} `json:"user_metadata"`
	Role                          string                 `json:"role"`
	AuthenticatorAssuranceLevel   string                 `json:"aal,omitempty"`
	AuthenticationMethodReference []models.AMREntry      `json:"amr,omitempty"`
	SessionId                     string                 `json:"session_id,omitempty"`
	IsAnonymous                   bool                   `json:"is_anonymous"`
}

type MFAVerificationAttemptInput struct {
	UserID     uuid.UUID `json:"user_id"`
	FactorID   uuid.UUID `json:"factor_id"`
	FactorType string    `json:"factor_type"`
	Valid      bool      `json:"valid"`
}

type MFAVerificationAttemptOutput struct {
	Decision  string        `json:"decision"`
	Message   string        `json:"message"`
	HookError AuthHookError `json:"error"`
}

type PasswordVerificationAttemptInput struct {
	UserID uuid.UUID `json:"user_id"`
	Valid  bool      `json:"valid"`
}

type PasswordVerificationAttemptOutput struct {
	Decision         string        `json:"decision"`
	Message          string        `json:"message"`
	ShouldLogoutUser bool          `json:"should_logout_user"`
	HookError        AuthHookError `json:"error"`
}

type CustomAccessTokenInput struct {
	UserID               uuid.UUID          `json:"user_id"`
	Claims               *AccessTokenClaims `json:"claims"`
	AuthenticationMethod string             `json:"authentication_method"`
}

type CustomAccessTokenOutput struct {
	Claims    map[string]interface{} `json:"claims"`
	HookError AuthHookError          `json:"error,omitempty"`
}

type SendSMSInput struct {
	User *models.User `json:"user,omitempty"`
	SMS  SMS          `json:"sms,omitempty"`
}

type SendSMSOutput struct {
	HookError AuthHookError `json:"error,omitempty"`
}

type SendEmailInput struct {
	User      *models.User     `json:"user"`
	EmailData mailer.EmailData `json:"email_data"`
}

type SendEmailOutput struct {
	HookError AuthHookError `json:"error,omitempty"`
}

func (mf *MFAVerificationAttemptOutput) IsError() bool {
	return mf.HookError.Message != ""
}

func (mf *MFAVerificationAttemptOutput) Error() string {
	return mf.HookError.Message
}

func (mf *MFAVerificationAttemptOutput) GetHookError() AuthHookError { return mf.HookError }

func (p *PasswordVerificationAttemptOutput) IsError() bool {
	return p.HookError.Message != ""
}

func (p *PasswordVerificationAttemptOutput) Error() string {
	return p.HookError.Message
}

func (p *PasswordVerificationAttemptOutput) GetHookError() AuthHookError { return p.HookError }

func (ca *CustomAccessTokenOutput) IsError() bool {
	return ca.HookError.Message != ""
}

func (ca *CustomAccessTokenOutput) Error() string {
	return ca.HookError.Message
}

func (ca *CustomAccessTokenOutput) GetHookError() AuthHookError { return ca.HookError }

func (cs *SendSMSOutput) IsError() bool {
	return cs.HookError.Message != ""
}

func (cs *SendSMSOutput) Error() string {
	return cs.HookError.Message
}

func (cs *SendSMSOutput) GetHookError() AuthHookError { return cs.HookError }

func (cs *SendEmailOutput) IsError() bool {
	return cs.HookError.Message != ""
}

func (cs *SendEmailOutput) Error() string {
	return cs.HookError.Message
}

func (cs *SendEmailOutput) GetHookError() AuthHookError { return cs.HookError }

type AuthHookError struct {
	HTTPCode int    `json:"http_code,omitempty"`
	Message  string `json:"message,omitempty"`
}

func (a *AuthHookError) Error() string {
	return a.Message
}

const (
	DefaultMFAHookRejectionMessage      = "Further MFA verification attempts will be rejected."
	DefaultPasswordHookRejectionMessage = "Further password verification attempts will be rejected."
)
