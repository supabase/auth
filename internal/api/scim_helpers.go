package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// requireSSOIdentity returns the SSO identity for the given provider type,
// or an internal server error if it doesn't exist. Use this in mutation paths
// where the user has already been confirmed to belong to the provider — a
// missing identity indicates data inconsistency.
func requireSSOIdentity(user *models.User, providerType string) (*models.Identity, error) {
	identity := findSSOIdentity(user, providerType)
	if identity == nil {
		return nil, apierrors.NewSCIMInternalServerError(
			fmt.Sprintf("SSO identity not found for provider %s", providerType))
	}
	return identity, nil
}

func setSCIMExternalID(tx *storage.Connection, identity *models.Identity, externalID string) error {
	if strings.TrimSpace(externalID) == "" {
		return apierrors.NewSCIMBadRequestError("externalId must not be empty", "invalidValue")
	}

	identity.ProviderID = externalID
	if identity.IdentityData == nil {
		identity.IdentityData = make(map[string]interface{})
	}
	identity.IdentityData["external_id"] = externalID
	identity.IdentityData["sub"] = externalID
	if err := tx.UpdateOnly(identity, "provider_id", "identity_data"); err != nil {
		if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
			return apierrors.NewSCIMConflictError(scimErrExternalIDConflict, "uniqueness")
		}
		return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
	}
	return nil
}

func setSCIMUserName(tx *storage.Connection, identity *models.Identity, userName string) error {
	if identity.IdentityData == nil {
		identity.IdentityData = make(map[string]interface{})
	}
	identity.IdentityData["user_name"] = userName

	updateCols := []string{"identity_data"}
	if externalID, ok := identity.IdentityData["external_id"].(string); !ok || externalID == "" {
		identity.ProviderID = userName
		identity.IdentityData["sub"] = userName
		updateCols = append(updateCols, "provider_id")
	}

	if err := tx.UpdateOnly(identity, updateCols...); err != nil {
		if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
			return apierrors.NewSCIMConflictError(scimErrUserNameConflict, "uniqueness")
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

// extractPrimarySCIMEmailRaw finds the primary email from a raw JSON emails
// array ([]interface{} of map[string]interface{}). Returns the primary entry's
// value, or the first entry's value if none is marked primary. Returns an error
// if any entry is malformed or no valid email value is found.
func extractPrimarySCIMEmailRaw(emails []interface{}) (string, error) {
	var firstValue string
	for _, entry := range emails {
		obj, ok := entry.(map[string]interface{})
		if !ok {
			return "", apierrors.NewSCIMBadRequestError("each email entry must be an object", "invalidValue")
		}
		val, _ := obj["value"].(string)
		if val == "" {
			return "", apierrors.NewSCIMBadRequestError("each email entry must have a string 'value'", "invalidValue")
		}
		if firstValue == "" {
			firstValue = val
		}
		if primary, _ := obj["primary"].(bool); primary {
			return val, nil
		}
	}
	return firstValue, nil
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
			return apierrors.NewSCIMConflictError(scimErrGroupExternalIDConflict, "uniqueness")
		}
		return apierrors.NewSCIMInternalServerError("Error updating group external ID").WithInternalError(err)
	}
	return nil
}

func scimDeprovisionUser(tx *storage.Connection, user *models.User) error {
	if user.IsBanned() && !user.IsSCIMDeprovisioned() {
		return apierrors.NewSCIMConflictError("User is banned by an administrator and cannot be deprovisioned via SCIM", "")
	}
	if err := user.Ban(tx, 200*365*24*time.Hour, &scimDeprovisionedReason); err != nil {
		return apierrors.NewSCIMInternalServerError("Error deprovisioning user").WithInternalError(err)
	}
	if err := models.Logout(tx, user.ID); err != nil {
		return apierrors.NewSCIMInternalServerError("Error invalidating sessions").WithInternalError(err)
	}
	return nil
}

func scimReactivateUser(tx *storage.Connection, user *models.User) error {
	if !user.IsBanned() {
		return nil
	}
	if !user.IsSCIMDeprovisioned() {
		return apierrors.NewSCIMConflictError("User is banned by an administrator and cannot be reactivated via SCIM", "")
	}
	if err := user.Ban(tx, 0, nil); err != nil {
		return apierrors.NewSCIMInternalServerError("Error reactivating user").WithInternalError(err)
	}
	return nil
}

func syncSCIMIdentity(tx *storage.Connection, identity *models.Identity, userName, email, externalID string) error {
	if identity.IdentityData == nil {
		identity.IdentityData = make(map[string]interface{})
	}
	identity.IdentityData["user_name"] = userName
	if email != "" {
		identity.IdentityData["email"] = email
	}
	if externalID != "" {
		identity.ProviderID = externalID
		identity.IdentityData["external_id"] = externalID
		identity.IdentityData["sub"] = externalID
	} else {
		delete(identity.IdentityData, "external_id")
		identity.ProviderID = userName
		identity.IdentityData["sub"] = userName
	}
	if err := tx.UpdateOnly(identity, "provider_id", "identity_data"); err != nil {
		if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
			return apierrors.NewSCIMConflictError(scimErrExternalIDConflict, "uniqueness")
		}
		return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
	}
	return nil
}

func mapGroupMemberError(err error, fallbackMsg string) error {
	if models.IsNotFoundError(err) {
		return apierrors.NewSCIMNotFoundError(scimErrMembersNotFound)
	}
	if _, ok := err.(models.UserNotInSSOProviderError); ok {
		return apierrors.NewSCIMBadRequestError(scimErrMembersWrongProvider, "invalidValue")
	}
	return apierrors.NewSCIMInternalServerError(fallbackMsg).WithInternalError(err)
}

func handleSCIMUniqueViolation(err error, conflictMsg, scimType, genericMsg string) error {
	if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
		return apierrors.NewSCIMConflictError(conflictMsg, scimType)
	}
	return apierrors.NewSCIMInternalServerError(genericMsg).WithInternalError(err)
}

func checkSCIMEmailUniqueness(tx *storage.Connection, email, aud, providerType string, excludeUserID uuid.UUID) error {
	existingUser, err := models.FindUserByEmailAndAudience(tx, email, aud)
	if err != nil && !models.IsNotFoundError(err) {
		return apierrors.NewSCIMInternalServerError("Error checking email uniqueness").WithInternalError(err)
	}
	if existingUser != nil && existingUser.ID != excludeUserID {
		if !existingUser.IsSSOUser {
			return apierrors.NewSCIMConflictError(scimErrEmailConflict, "uniqueness")
		}
		if existingUser.BannedReason == nil || *existingUser.BannedReason != scimDeprovisionedReason {
			return apierrors.NewSCIMConflictError(scimErrEmailConflict, "uniqueness")
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
			return apierrors.NewSCIMConflictError(scimErrEmailConflict, "uniqueness")
		}
	}
	return nil
}
