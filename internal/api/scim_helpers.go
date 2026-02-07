package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

func parseSCIMPagination(r *http.Request) (startIndex, count int) {
	startIndex = 1
	count = SCIMDefaultPageSize

	if v := r.URL.Query().Get("startIndex"); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			startIndex = i
			if startIndex > SCIMMaxStartIndex {
				startIndex = SCIMMaxStartIndex
			}
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

func (a *API) parseSCIMBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, SCIMMaxBodySize)
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
			if identity.IdentityData != nil {
				if extID, ok := identity.IdentityData["external_id"].(string); ok && extID != "" {
					resp.ExternalID = extID
				}
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

func parseSCIMActiveBool(val interface{}) (bool, error) {
	switch v := val.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(v) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, apierrors.NewSCIMBadRequestError("active must be a boolean or \"true\"/\"false\"", "invalidValue")
}

func findSSOIdentity(user *models.User, providerType string) *models.Identity {
	for i := range user.Identities {
		if user.Identities[i].Provider == providerType {
			return &user.Identities[i]
		}
	}
	return nil
}

func setSCIMExternalID(tx *storage.Connection, identity *models.Identity, externalID string) error {
	identity.ProviderID = externalID
	if identity.IdentityData == nil {
		identity.IdentityData = make(map[string]interface{})
	}
	identity.IdentityData["external_id"] = externalID
	identity.IdentityData["sub"] = externalID
	if err := tx.UpdateOnly(identity, "provider_id", "identity_data"); err != nil {
		if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
			return apierrors.NewSCIMConflictError("User with this externalId already exists", "uniqueness")
		}
		return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
	}
	return nil
}

func setSCIMIdentityField(tx *storage.Connection, identity *models.Identity, key, value string) error {
	if identity.IdentityData == nil {
		identity.IdentityData = make(map[string]interface{})
	}
	identity.IdentityData[key] = value
	if err := tx.UpdateOnly(identity, "identity_data"); err != nil {
		return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
	}
	return nil
}

func extractPrimarySCIMEmail(emails []SCIMEmail) (email, emailType string) {
	if len(emails) == 0 {
		return "", ""
	}
	for _, e := range emails {
		if e.Primary {
			return e.Value, e.Type
		}
	}
	return emails[0].Value, emails[0].Type
}

func applySCIMNameToMetadata(metadata map[string]interface{}, name *SCIMName) {
	if name == nil {
		return
	}
	if name.GivenName != "" {
		metadata["given_name"] = name.GivenName
	}
	if name.FamilyName != "" {
		metadata["family_name"] = name.FamilyName
	}
	if name.Formatted != "" {
		metadata["full_name"] = name.Formatted
	}
}

func parseSCIMGroupMemberRefs(members []SCIMGroupMemberRef) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(members))
	for _, member := range members {
		id, err := uuid.FromString(member.Value)
		if err != nil {
			return nil, apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid member ID: %s", member.Value), "invalidValue")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func parseSCIMGroupMemberIDsRaw(members []interface{}) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, len(members))
	for _, m := range members {
		memberMap, ok := m.(map[string]interface{})
		if !ok {
			return nil, apierrors.NewSCIMBadRequestError("Invalid member format", "invalidValue")
		}
		value, ok := memberMap["value"].(string)
		if !ok {
			return nil, apierrors.NewSCIMBadRequestError("Member value must be a string", "invalidValue")
		}
		id, err := uuid.FromString(value)
		if err != nil {
			return nil, apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid member ID: %s", value), "invalidValue")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func updateGroupExternalID(tx *storage.Connection, group *models.SCIMGroup, externalID string) error {
	group.ExternalID = storage.NullString(externalID)
	if err := tx.UpdateOnly(group, "external_id"); err != nil {
		if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
			return apierrors.NewSCIMConflictError("Group with this externalId already exists", "uniqueness")
		}
		return apierrors.NewSCIMInternalServerError("Error updating group external ID").WithInternalError(err)
	}
	return nil
}

func checkSCIMEmailUniqueness(tx *storage.Connection, email, aud, providerType string, excludeUserID uuid.UUID) error {
	existingUser, err := models.FindUserByEmailAndAudience(tx, email, aud)
	if err != nil && !models.IsNotFoundError(err) {
		return apierrors.NewSCIMInternalServerError("Error checking email uniqueness").WithInternalError(err)
	}
	if existingUser != nil && existingUser.ID != excludeUserID {
		if !existingUser.IsSSOUser {
			return apierrors.NewSCIMConflictError("Email already in use by another user", "uniqueness")
		}
		if existingUser.BannedReason == nil || *existingUser.BannedReason != scimDeprovisionedReason {
			return apierrors.NewSCIMConflictError("Email already in use by another user", "uniqueness")
		}
	}

	ssoUsers, err := models.FindSSOUsersByEmailAndProvider(tx, email, aud, providerType)
	if err != nil {
		return apierrors.NewSCIMInternalServerError("Error checking email uniqueness").WithInternalError(err)
	}
	for _, u := range ssoUsers {
		if u.ID == excludeUserID {
			continue
		}
		if u.BannedReason == nil || *u.BannedReason != scimDeprovisionedReason {
			return apierrors.NewSCIMConflictError("Email already in use by another user", "uniqueness")
		}
	}
	return nil
}
