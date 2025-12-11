package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/utilities"
)

// parseSCIMPagination extracts startIndex and count from SCIM query parameters.
// startIndex is 1-indexed per SCIM spec, count defaults to SCIMDefaultPageSize.
func parseSCIMPagination(r *http.Request) (startIndex, count int) {
	startIndex = 1
	count = SCIMDefaultPageSize

	if v := r.URL.Query().Get("startIndex"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			startIndex = i
		}
	}

	if v := r.URL.Query().Get("count"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			count = i
			if count > SCIMMaxPageSize {
				count = SCIMMaxPageSize
			}
		}
	}

	return startIndex, count
}

// parseSCIMFilter extracts a value from a SCIM filter expression for the given attribute.
// Supports: attributeName eq "value" (case-insensitive attribute name per RFC 7644)
// Returns empty string if no valid filter found.
func parseSCIMFilter(filter, attributeName string) string {
	if filter == "" {
		return ""
	}
	filter = strings.TrimSpace(filter)
	lower := strings.ToLower(filter)
	expectedPrefix := strings.ToLower(attributeName) + " eq "

	if strings.HasPrefix(lower, expectedPrefix) {
		rest := filter[len(attributeName)+4:] // " eq " = 4 chars
		rest = strings.TrimSpace(rest)
		if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
			return rest[1 : len(rest)-1]
		}
	}
	return ""
}

// parseSCIMBody parses the request body as JSON into the provided struct.
func (a *API) parseSCIMBody(r *http.Request, v interface{}) error {
	body, err := utilities.GetBodyBytes(r)
	if err != nil {
		return apierrors.NewInternalServerError("Could not read request body").WithInternalError(err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid JSON: %v", err), "invalidSyntax")
	}
	return nil
}

// userBelongsToProvider checks if a user has an identity linked to the given SSO provider.
func userBelongsToProvider(user *models.User, providerID uuid.UUID) bool {
	providerType := "sso:" + providerID.String()
	for _, identity := range user.Identities {
		if identity.Provider == providerType {
			return true
		}
	}
	return false
}

// userToSCIMResponse converts a User model to a SCIM User response.
func (a *API) userToSCIMResponse(user *models.User) *SCIMUserResponse {
	baseURL := a.getSCIMBaseURL()
	resp := &SCIMUserResponse{
		Schemas:  []string{SCIMSchemaUser},
		ID:       user.ID.String(),
		UserName: user.GetEmail(), // Default to email, will be overwritten if userName stored in identity
		Active:   !user.IsBanned(),
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      &user.CreatedAt,
			LastModified: &user.UpdatedAt,
			Location:     baseURL + "/scim/v2/Users/" + user.ID.String(),
		},
	}

	// Set external ID, userName, and email type from SSO identity if available
	var emailType string
	for _, identity := range user.Identities {
		if strings.HasPrefix(identity.Provider, "sso:") {
			if identity.ProviderID != "" {
				resp.ExternalID = identity.ProviderID
			}
			// Get userName and email_type from identity metadata if stored
			if identity.IdentityData != nil {
				if userName, ok := identity.IdentityData["user_name"].(string); ok && userName != "" {
					resp.UserName = userName
				}
				if et, ok := identity.IdentityData["email_type"].(string); ok {
					emailType = et
				}
			}
			break
		}
	}

	if email := user.GetEmail(); email != "" {
		scimEmail := SCIMEmail{Value: email, Primary: true}
		// Only include type if it was originally provided (not empty)
		if emailType != "" {
			scimEmail.Type = emailType
		}
		resp.Emails = []SCIMEmail{scimEmail}
	}

	if user.UserMetaData != nil {
		name := &SCIMName{}
		hasName := false
		if v, ok := user.UserMetaData["given_name"].(string); ok {
			name.GivenName = v
			hasName = true
		}
		if v, ok := user.UserMetaData["family_name"].(string); ok {
			name.FamilyName = v
			hasName = true
		}
		if v, ok := user.UserMetaData["full_name"].(string); ok {
			name.Formatted = v
			hasName = true
		}
		if hasName {
			resp.Name = name
		}
	}

	return resp
}

// groupToSCIMResponse converts a SCIMGroup model to a SCIM Group response.
func (a *API) groupToSCIMResponse(group *models.SCIMGroup, members []*models.User) *SCIMGroupResponse {
	baseURL := a.getSCIMBaseURL()
	resp := &SCIMGroupResponse{
		Schemas:     []string{SCIMSchemaGroup},
		ID:          group.ID.String(),
		ExternalID:  string(group.ExternalID),
		DisplayName: group.DisplayName,
		Members:     []SCIMGroupMemberRef{}, // Always include members, empty array if none
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      &group.CreatedAt,
			LastModified: &group.UpdatedAt,
			Location:     baseURL + "/scim/v2/Groups/" + group.ID.String(),
		},
	}

	if len(members) > 0 {
		resp.Members = make([]SCIMGroupMemberRef, len(members))
		for i, m := range members {
			resp.Members[i] = SCIMGroupMemberRef{
				Value:   m.ID.String(),
				Ref:     baseURL + "/scim/v2/Users/" + m.ID.String(),
				Display: m.GetEmail(),
			}
		}
	}

	return resp
}

// getSCIMBaseURL returns the base URL for SCIM resource locations.
func (a *API) getSCIMBaseURL() string {
	return a.config.SiteURL
}

// sendSCIMJSON sends a JSON response with SCIM content type.
func sendSCIMJSON(w http.ResponseWriter, status int, obj interface{}) error {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(obj)
}
