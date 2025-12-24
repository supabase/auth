package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/supabase/auth/internal/api/apierrors"
)

const (
	SCIMDefaultPageSize    = 100
	SCIMMaxPageSize        = 1000
	SCIMSchemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	SCIMSchemaGroup        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SCIMSchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SCIMSchemaPatchOp      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SCIMSchemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Must be var (not const) because it's passed by pointer to user.Ban()
var scimDeprovisionedReason = "SCIM_DEPROVISIONED"

// FlexBool handles both bool and string ("true"/"false") - Azure AD sends strings
type FlexBool bool

func (fb *FlexBool) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*fb = FlexBool(b)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*fb = FlexBool(strings.ToLower(s) == "true")
		return nil
	}
	return fmt.Errorf("cannot unmarshal %s into FlexBool", string(data))
}

type SCIMUserParams struct {
	Schemas    []string    `json:"schemas"`
	ExternalID string      `json:"externalId"`
	UserName   string      `json:"userName"`
	Name       *SCIMName   `json:"name,omitempty"`
	Emails     []SCIMEmail `json:"emails,omitempty"`
	Active     *bool       `json:"active,omitempty"`
}

func (p *SCIMUserParams) Validate() error {
	if p.UserName == "" {
		return apierrors.NewSCIMBadRequestError("userName is required", "invalidSyntax")
	}
	return nil
}

type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

type SCIMEmail struct {
	Value   string   `json:"value"`
	Type    string   `json:"type,omitempty"`
	Primary FlexBool `json:"primary,omitempty"`
}

type SCIMGroupParams struct {
	Schemas     []string             `json:"schemas"`
	ExternalID  string               `json:"externalId"`
	DisplayName string               `json:"displayName"`
	Members     []SCIMGroupMemberRef `json:"members,omitempty"`
}

func (p *SCIMGroupParams) Validate() error {
	if p.DisplayName == "" {
		return apierrors.NewSCIMBadRequestError("displayName is required", "invalidSyntax")
	}
	return nil
}

type SCIMGroupMemberRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
}

type SCIMPatchRequest struct {
	Schemas    []string             `json:"schemas"`
	Operations []SCIMPatchOperation `json:"Operations"`
}

type SCIMPatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

type SCIMMeta struct {
	ResourceType string     `json:"resourceType"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
}

type SCIMUserResponse struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       *SCIMName   `json:"name,omitempty"`
	Emails     []SCIMEmail `json:"emails,omitempty"`
	Active     bool        `json:"active"`
	Meta       SCIMMeta    `json:"meta"`
}

type SCIMGroupResponse struct {
	Schemas     []string             `json:"schemas"`
	ID          string               `json:"id"`
	ExternalID  string               `json:"externalId,omitempty"`
	DisplayName string               `json:"displayName"`
	Members     []SCIMGroupMemberRef `json:"members,omitempty"`
	Meta        SCIMMeta             `json:"meta"`
}

type SCIMListResponse struct {
	Schemas      []string      `json:"schemas"`
	TotalResults int           `json:"totalResults"`
	StartIndex   int           `json:"startIndex"`
	ItemsPerPage int           `json:"itemsPerPage"`
	Resources    []interface{} `json:"Resources"`
}

type SCIMErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	ScimType string   `json:"scimType,omitempty"`
}

func NewSCIMError(status int, detail string, scimType string) *SCIMErrorResponse {
	return &SCIMErrorResponse{
		Schemas:  []string{SCIMSchemaError},
		Status:   strconv.Itoa(status),
		Detail:   detail,
		ScimType: scimType,
	}
}
