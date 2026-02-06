package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/utilities"
)

func parseSCIMPagination(r *http.Request) (startIndex, count int) {
	startIndex = 1
	count = SCIMDefaultPageSize

	if v := r.URL.Query().Get("startIndex"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			startIndex = i
		}
	}

	if v := r.URL.Query().Get("count"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i >= 0 {
			count = i
			if count > SCIMMaxPageSize {
				count = SCIMMaxPageSize
			}
		}
	}

	return startIndex, count
}

func (a *API) parseSCIMBody(r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(nil, r.Body, SCIMMaxBodySize)
	body, err := utilities.GetBodyBytes(r)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return apierrors.NewSCIMRequestTooLargeError("Request body exceeds maximum size of 1MB")
		}
		return apierrors.NewSCIMInternalServerError("Could not read request body").WithInternalError(err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return apierrors.NewSCIMBadRequestError("Invalid JSON in request body", "invalidSyntax").WithInternalError(err)
	}
	return nil
}

func (a *API) userToSCIMResponse(user *models.User, providerType string) *SCIMUserResponse {
	baseURL := a.getSCIMBaseURL()
	resp := &SCIMUserResponse{
		Schemas:  []string{SCIMSchemaUser},
		ID:       user.ID.String(),
		UserName: user.GetEmail(),
		Active:   !user.IsBanned(),
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      &user.CreatedAt,
			LastModified: &user.UpdatedAt,
			Location:     baseURL + "/scim/v2/Users/" + user.ID.String(),
		},
	}

	var emailType string
	for _, identity := range user.Identities {
		if identity.Provider == providerType {
			if identity.ProviderID != "" {
				resp.ExternalID = identity.ProviderID
			}
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

func (a *API) groupToSCIMResponse(group *models.SCIMGroup, members []*models.User) *SCIMGroupResponse {
	baseURL := a.getSCIMBaseURL()
	resp := &SCIMGroupResponse{
		Schemas:     []string{SCIMSchemaGroup},
		ID:          group.ID.String(),
		ExternalID:  string(group.ExternalID),
		DisplayName: group.DisplayName,
		Members:     []SCIMGroupMemberRef{},
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

func (a *API) getSCIMBaseURL() string {
	return strings.TrimRight(a.config.API.ExternalURL, "/")
}

func sendSCIMJSON(w http.ResponseWriter, status int, obj interface{}) error {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(obj)
}
