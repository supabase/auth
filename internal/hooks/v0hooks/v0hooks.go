package v0hooks

import (
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/utilities"
)

type Name string

const (
	SendSMS              Name = "send-sms"
	SendEmail            Name = "send-email"
	CustomizeAccessToken Name = "customize-access-token"
	MFAVerification      Name = "mfa-verification"
	PasswordVerification Name = "password-verification"
	BeforeUserCreated    Name = "before-user-created"
	AfterUserCreated     Name = "after-user-created"
)

const (
	HookRejection = "reject"
)

const (
	DefaultMFAHookRejectionMessage      = "Further MFA verification attempts will be rejected."
	DefaultPasswordHookRejectionMessage = "Further password verification attempts will be rejected."
)

type Header struct {
	UUID uuid.UUID `json:"uuid"`
	Time time.Time `json:"time"`

	// Hook name
	Name Name `json:"name,omitempty"`

	// IP Address of the request, if present
	IPAddress string `json:"ip_address,omitempty"`
}

func NewHeader(r *http.Request, name Name) *Header {
	return &Header{
		UUID:      uuid.Must(uuid.NewV4()),
		Time:      time.Now(),
		IPAddress: utilities.GetIPAddress(r),
		Name:      name,
	}
}

type BeforeUserCreatedRequest struct {
	Header *Header      `json:"header"`
	User   *models.User `json:"user"`
}

func NewBeforeUserCreatedRequest(
	r *http.Request,
	user *models.User,
) *BeforeUserCreatedRequest {
	return &BeforeUserCreatedRequest{
		Header: NewHeader(r, BeforeUserCreated),
		User:   user,
	}
}

type BeforeUserCreatedResponse struct{}

type AfterUserCreatedRequest struct {
	Header *Header      `json:"header"`
	User   *models.User `json:"user"`
}

func NewAfterUserCreatedRequest(
	r *http.Request,
	user *models.User,
) *AfterUserCreatedRequest {
	return &AfterUserCreatedRequest{
		Header: NewHeader(r, AfterUserCreated),
		User:   user,
	}
}

type AfterUserCreatedResponse struct{}

// TODO(joel): Move this to phone package
type SMS struct {
	OTP     string `json:"otp,omitempty"`
	SMSType string `json:"sms_type,omitempty"`
}

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
	Decision string `json:"decision"`
	Message  string `json:"message"`
}

type PasswordVerificationAttemptInput struct {
	UserID uuid.UUID `json:"user_id"`
	Valid  bool      `json:"valid"`
}

type PasswordVerificationAttemptOutput struct {
	Decision         string `json:"decision"`
	Message          string `json:"message"`
	ShouldLogoutUser bool   `json:"should_logout_user"`
}

type CustomAccessTokenInput struct {
	UserID               uuid.UUID          `json:"user_id"`
	Claims               *AccessTokenClaims `json:"claims"`
	AuthenticationMethod string             `json:"authentication_method"`
}

type CustomAccessTokenOutput struct {
	Claims map[string]interface{} `json:"claims"`
}

type SendSMSInput struct {
	User *models.User `json:"user,omitempty"`
	SMS  SMS          `json:"sms,omitempty"`
}

type SendSMSOutput struct {
}

type SendEmailInput struct {
	User      *models.User     `json:"user"`
	EmailData mailer.EmailData `json:"email_data"`
}

type SendEmailOutput struct {
}
