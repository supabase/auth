package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/supabase/auth/internal/api/apierrors"
)

const (
	SCIMDefaultPageSize    = 100
	SCIMMaxPageSize        = 1000
	SCIMMaxBodySize        = 1 << 20 // 1 MB
	SCIMMaxMembers         = 1000
	SCIMMaxPatchOperations = 100
	SCIMMaxStartIndex      = 100000
	SCIMSchemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	SCIMSchemaGroup        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SCIMSchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SCIMSchemaPatchOp      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

	scimErrUserNotFound              = "User not found"
	scimErrGroupNotFound             = "Group not found"
	scimErrEmailConflict             = "Email already in use by another user"
	scimErrExternalIDConflict        = "User with this externalId already exists"
	scimErrUserNameConflict          = "User with this userName already exists"
	scimErrGroupExternalIDConflict   = "Group with this externalId already exists"
	scimErrGroupDisplayNameConflict  = "Group with this displayName already exists"
	scimErrMembersNotFound           = "One or more members not found"
	scimErrMembersWrongProvider      = "One or more members do not belong to this SSO provider"
	scimErrAmbiguousDeprovisioned    = "Multiple deprovisioned users exist for this email"
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
		switch strings.ToLower(s) {
		case "true":
			*fb = FlexBool(true)
		case "false":
			*fb = FlexBool(false)
		default:
			return fmt.Errorf("cannot unmarshal %q into FlexBool: must be true or false", s)
		}
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
	Active     *FlexBool   `json:"active,omitempty"`
}

func (p *SCIMUserParams) Validate() error {
	if err := requireSCIMSchema(p.Schemas, SCIMSchemaUser); err != nil {
		return err
	}
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
	if err := requireSCIMSchema(p.Schemas, SCIMSchemaGroup); err != nil {
		return err
	}
	if p.DisplayName == "" {
		return apierrors.NewSCIMBadRequestError("displayName is required", "invalidSyntax")
	}
	if len(p.Members) > SCIMMaxMembers {
		return apierrors.NewSCIMRequestTooLargeError(fmt.Sprintf("Maximum %d members per request", SCIMMaxMembers))
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

func (p *SCIMPatchRequest) Validate() error {
	if err := requireSCIMSchema(p.Schemas, SCIMSchemaPatchOp); err != nil {
		return err
	}
	if len(p.Operations) == 0 {
		return apierrors.NewSCIMBadRequestError("At least one operation is required", "invalidSyntax")
	}
	if len(p.Operations) > SCIMMaxPatchOperations {
		return apierrors.NewSCIMRequestTooLargeError(fmt.Sprintf("Maximum %d operations per request", SCIMMaxPatchOperations))
	}
	return nil
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

func requireSCIMSchema(schemas []string, required string) error {
	for _, s := range schemas {
		if s == required {
			return nil
		}
	}
	return apierrors.NewSCIMBadRequestError(
		fmt.Sprintf("schemas must include %s", required),
		"invalidValue",
	)
}
