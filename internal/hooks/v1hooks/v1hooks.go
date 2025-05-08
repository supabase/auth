package v1hooks

import (
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/utilities"
)

const (
	BeforeUserCreated v0hooks.Name = "before-user-created"
	AfterUserCreated  v0hooks.Name = "after-user-created"
)

type Header struct {
	UUID uuid.UUID `json:"uuid"`
	Time time.Time `json:"time"`

	// Hook name
	Name v0hooks.Name `json:"name,omitempty"`

	// IP Address of the request, if present
	IPAddress string `json:"ip_address,omitempty"`
}

func NewHeader(r *http.Request, name v0hooks.Name) *Header {
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
