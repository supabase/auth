package api

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

const (
	SCIMDefaultPageSize    = 100
	SCIMMaxPageSize        = 1000
	SCIMSchemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	SCIMSchemaGroup        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SCIMSchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SCIMSchemaPatchOp      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

var scimDeprovisionedReason = "SCIM_DEPROVISIONED"

// SCIM request/response types - using camelCase per SCIM v2 spec (RFC 7643)

type SCIMUserParams struct {
	Schemas    []string    `json:"schemas"`
	ExternalID string      `json:"externalId"`
	UserName   string      `json:"userName"`
	Name       *SCIMName   `json:"name,omitempty"`
	Emails     []SCIMEmail `json:"emails,omitempty"`
	Active     *bool       `json:"active,omitempty"`
}

type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type SCIMGroupParams struct {
	Schemas     []string             `json:"schemas"`
	ExternalID  string               `json:"externalId"`
	DisplayName string               `json:"displayName"`
	Members     []SCIMGroupMemberRef `json:"members,omitempty"`
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

// Validation methods

func (p *SCIMUserParams) Validate() error {
	if p.UserName == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "userName is required")
	}
	return nil
}

func (p *SCIMGroupParams) Validate() error {
	if p.DisplayName == "" {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "displayName is required")
	}
	return nil
}

// SCIM Authentication Middleware

func (a *API) requireSCIMAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	token, err := a.extractBearerToken(r)
	if err != nil {
		return nil, apierrors.NewHTTPError(http.StatusUnauthorized, apierrors.ErrorCodeSCIMTokenInvalid, "Invalid or missing SCIM bearer token")
	}

	provider, err := models.FindSSOProviderBySCIMToken(ctx, db, token)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, apierrors.NewHTTPError(http.StatusUnauthorized, apierrors.ErrorCodeSCIMTokenInvalid, "Invalid SCIM bearer token")
		}
		return nil, apierrors.NewInternalServerError("Error validating SCIM token").WithInternalError(err)
	}

	if !provider.IsSCIMEnabled() {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeSCIMDisabled, "SCIM provisioning is not enabled for this provider")
	}

	if !provider.IsEnabled() {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeSSOProviderDisabled, "SSO provider is disabled")
	}

	return withSSOProvider(ctx, provider), nil
}

// Helper functions

func (a *API) getSCIMBaseURL() string {
	return a.config.SiteURL
}

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

func userBelongsToProvider(user *models.User, providerID uuid.UUID) bool {
	providerType := "sso:" + providerID.String()
	for _, identity := range user.Identities {
		if identity.Provider == providerType {
			return true
		}
	}
	return false
}

func (a *API) userToSCIMResponse(user *models.User) *SCIMUserResponse {
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

	// Set external ID from identity if available
	for _, identity := range user.Identities {
		if identity.Provider != "" && identity.ProviderID != "" {
			resp.ExternalID = identity.ProviderID
			break
		}
	}

	if email := user.GetEmail(); email != "" {
		resp.Emails = []SCIMEmail{{Value: email, Type: "work", Primary: true}}
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
		ExternalID:  group.ExternalID,
		DisplayName: group.DisplayName,
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      &group.CreatedAt,
			LastModified: &group.UpdatedAt,
			Location:     baseURL + "/scim/v2/Groups/" + group.ID.String(),
		},
	}

	if members != nil {
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

func (a *API) parseSCIMBody(r *http.Request, v interface{}) error {
	body, err := utilities.GetBodyBytes(r)
	if err != nil {
		return apierrors.NewInternalServerError("Could not read request body").WithInternalError(err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Invalid JSON: %v", err)
	}
	return nil
}

// User Endpoints

func (a *API) scimListUsers(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	startIndex, count := parseSCIMPagination(r)

	providerType := "sso:" + provider.ID.String()

	totalResults, err := models.CountUsersByProvider(db, providerType)
	if err != nil {
		return apierrors.NewInternalServerError("Error counting users").WithInternalError(err)
	}

	users, err := models.FindUsersByProvider(db, providerType, startIndex, count)
	if err != nil {
		return apierrors.NewInternalServerError("Error fetching users").WithInternalError(err)
	}

	resources := make([]interface{}, len(users))
	for i, user := range users {
		resources[i] = a.userToSCIMResponse(user)
	}

	return sendJSON(w, http.StatusOK, &SCIMListResponse{
		Schemas:      []string{SCIMSchemaListResponse},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(users),
		Resources:    resources,
	})
}

func (a *API) scimGetUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	userID, err := uuid.FromString(chi.URLParam(r, "user_id"))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid user ID format")
	}

	user, err := models.FindUserByID(db, userID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMUserNotFound, "User not found")
		}
		return apierrors.NewInternalServerError("Error fetching user").WithInternalError(err)
	}

	if !userBelongsToProvider(user, provider.ID) {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMUserNotFound, "User not found")
	}

	return sendJSON(w, http.StatusOK, a.userToSCIMResponse(user))
}

// scimCreateUser handles POST /scim/v2/Users
func (a *API) scimCreateUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)
	config := a.config

	var params SCIMUserParams
	if err := a.parseSCIMBody(r, &params); err != nil {
		return err
	}
	if err := params.Validate(); err != nil {
		return err
	}

	email, err := a.validateEmail(params.UserName)
	if err != nil {
		return err
	}

	providerType := "sso:" + provider.ID.String()

	var user *models.User
	terr := db.Transaction(func(tx *storage.Connection) error {
		// Check if user exists and was deprovisioned
		existingUser, err := models.FindUserByEmailAndAudience(tx, email, config.JWT.Aud)
		if err != nil && !models.IsNotFoundError(err) {
			return apierrors.NewInternalServerError("Error checking existing user").WithInternalError(err)
		}

		if existingUser != nil {
			if existingUser.BannedReason != nil && *existingUser.BannedReason == scimDeprovisionedReason {
				// Reactivate deprovisioned user
				if err := existingUser.Ban(tx, 0, nil); err != nil {
					return apierrors.NewInternalServerError("Error reactivating user").WithInternalError(err)
				}
				if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, existingUser, models.UserModifiedAction, "", map[string]interface{}{
					"provider":        "scim",
					"sso_provider_id": provider.ID,
					"action":          "reactivated",
				}); terr != nil {
					return apierrors.NewInternalServerError("Error recording audit log entry").WithInternalError(terr)
				}
				user = existingUser
				return nil
			}
			return apierrors.NewHTTPError(http.StatusConflict, apierrors.ErrorCodeSCIMUserAlreadyExists, "User with this email already exists")
		}

		// Create new user
		user, err = models.NewUser("", email, "", config.JWT.Aud, nil)
		if err != nil {
			return apierrors.NewInternalServerError("Error creating user").WithInternalError(err)
		}
		user.IsSSOUser = true

		if params.Name != nil {
			metadata := make(map[string]interface{})
			if params.Name.GivenName != "" {
				metadata["given_name"] = params.Name.GivenName
			}
			if params.Name.FamilyName != "" {
				metadata["family_name"] = params.Name.FamilyName
			}
			if params.Name.Formatted != "" {
				metadata["full_name"] = params.Name.Formatted
			}
			if len(metadata) > 0 {
				user.UserMetaData = metadata
			}
		}

		if err := tx.Create(user); err != nil {
			return apierrors.NewInternalServerError("Error saving user").WithInternalError(err)
		}

		if _, err := a.createNewIdentity(tx, user, providerType, map[string]interface{}{
			"sub":         params.ExternalID,
			"external_id": params.ExternalID,
			"email":       email,
		}); err != nil {
			return err
		}

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserSignedUpAction, "", map[string]interface{}{
			"provider":        "scim",
			"sso_provider_id": provider.ID,
		}); terr != nil {
			return apierrors.NewInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		if err := tx.Eager().Find(user, user.ID); err != nil {
			return apierrors.NewInternalServerError("Error reloading user").WithInternalError(err)
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	return sendJSON(w, http.StatusCreated, a.userToSCIMResponse(user))
}

func (a *API) scimReplaceUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)
	config := a.config

	userID, err := uuid.FromString(chi.URLParam(r, "user_id"))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid user ID format")
	}

	var params SCIMUserParams
	if err := a.parseSCIMBody(r, &params); err != nil {
		return err
	}

	var user *models.User
	terr := db.Transaction(func(tx *storage.Connection) error {
		var err error
		user, err = models.FindUserByID(tx, userID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMUserNotFound, "User not found")
			}
			return apierrors.NewInternalServerError("Error fetching user").WithInternalError(err)
		}

		if !userBelongsToProvider(user, provider.ID) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMUserNotFound, "User not found")
		}

		if params.Name != nil {
			if user.UserMetaData == nil {
				user.UserMetaData = make(map[string]interface{})
			}
			if params.Name.GivenName != "" {
				user.UserMetaData["given_name"] = params.Name.GivenName
			}
			if params.Name.FamilyName != "" {
				user.UserMetaData["family_name"] = params.Name.FamilyName
			}
			if params.Name.Formatted != "" {
				user.UserMetaData["full_name"] = params.Name.Formatted
			}
		}

		if params.Active != nil {
			if *params.Active {
				if err := user.Ban(tx, 0, nil); err != nil {
					return apierrors.NewInternalServerError("Error unbanning user").WithInternalError(err)
				}
			} else {
				if err := user.Ban(tx, time.Duration(math.MaxInt64), &scimDeprovisionedReason); err != nil {
					return apierrors.NewInternalServerError("Error banning user").WithInternalError(err)
				}
				if err := models.Logout(tx, user.ID); err != nil {
					return apierrors.NewInternalServerError("Error invalidating sessions").WithInternalError(err)
				}
			}
		}

		if err := tx.UpdateOnly(user, "raw_user_meta_data"); err != nil {
			return apierrors.NewInternalServerError("Error updating user").WithInternalError(err)
		}

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserModifiedAction, "", map[string]interface{}{
			"provider":        "scim",
			"sso_provider_id": provider.ID,
		}); terr != nil {
			return apierrors.NewInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	return sendJSON(w, http.StatusOK, a.userToSCIMResponse(user))
}

func (a *API) scimPatchUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)
	config := a.config

	userID, err := uuid.FromString(chi.URLParam(r, "user_id"))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid user ID format")
	}

	var params SCIMPatchRequest
	if err := a.parseSCIMBody(r, &params); err != nil {
		return err
	}

	var user *models.User
	terr := db.Transaction(func(tx *storage.Connection) error {
		var err error
		user, err = models.FindUserByID(tx, userID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMUserNotFound, "User not found")
			}
			return apierrors.NewInternalServerError("Error fetching user").WithInternalError(err)
		}

		if !userBelongsToProvider(user, provider.ID) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMUserNotFound, "User not found")
		}

		for _, op := range params.Operations {
			if err := a.applySCIMUserPatch(tx, user, op); err != nil {
				return err
			}
		}

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserModifiedAction, "", map[string]interface{}{
			"provider":        "scim",
			"sso_provider_id": provider.ID,
		}); terr != nil {
			return apierrors.NewInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	return sendJSON(w, http.StatusOK, a.userToSCIMResponse(user))
}

func (a *API) applySCIMUserPatch(tx *storage.Connection, user *models.User, op SCIMPatchOperation) error {
	switch strings.ToLower(op.Op) {
	case "replace":
		switch strings.ToLower(op.Path) {
		case "active":
			active, ok := op.Value.(bool)
			if !ok {
				return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "active must be a boolean")
			}
			if active {
				return user.Ban(tx, 0, nil)
			}
			if err := user.Ban(tx, time.Duration(math.MaxInt64), &scimDeprovisionedReason); err != nil {
				return err
			}
			return models.Logout(tx, user.ID)
		case "":
			// Replace entire resource
			if valueMap, ok := op.Value.(map[string]interface{}); ok {
				if active, ok := valueMap["active"].(bool); ok {
					if active {
						return user.Ban(tx, 0, nil)
					}
					if err := user.Ban(tx, time.Duration(math.MaxInt64), &scimDeprovisionedReason); err != nil {
						return err
					}
					return models.Logout(tx, user.ID)
				}
			}
		}
	default:
		return apierrors.NewBadRequestError(apierrors.ErrorCodeSCIMMutuallyExclusive, "Unsupported patch operation: %s", op.Op)
	}
	return nil
}

// scimDeleteUser handles DELETE /scim/v2/Users/{id}
func (a *API) scimDeleteUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)
	config := a.config

	userID, err := uuid.FromString(chi.URLParam(r, "user_id"))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid user ID format")
	}

	terr := db.Transaction(func(tx *storage.Connection) error {
		user, err := models.FindUserByID(tx, userID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMUserNotFound, "User not found")
			}
			return apierrors.NewInternalServerError("Error fetching user").WithInternalError(err)
		}

		if !userBelongsToProvider(user, provider.ID) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMUserNotFound, "User not found")
		}

		// Soft delete: ban with infinity duration
		if err := user.Ban(tx, time.Duration(math.MaxInt64), &scimDeprovisionedReason); err != nil {
			return apierrors.NewInternalServerError("Error deprovisioning user").WithInternalError(err)
		}

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserDeletedAction, "", map[string]interface{}{
			"provider":        "scim",
			"sso_provider_id": provider.ID,
		}); terr != nil {
			return apierrors.NewInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		return models.Logout(tx, user.ID)
	})

	if terr != nil {
		return terr
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Group Endpoints

func (a *API) scimListGroups(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	startIndex, count := parseSCIMPagination(r)

	totalResults, err := models.CountSCIMGroupsBySSOProvider(db, provider.ID)
	if err != nil {
		return apierrors.NewInternalServerError("Error counting groups").WithInternalError(err)
	}

	groups, err := models.FindSCIMGroupsBySSOProvider(db, provider.ID, startIndex, count)
	if err != nil {
		return apierrors.NewInternalServerError("Error fetching groups").WithInternalError(err)
	}

	resources := make([]interface{}, len(groups))
	for i, group := range groups {
		members, _ := group.GetMembers(db)
		resources[i] = a.groupToSCIMResponse(group, members)
	}

	return sendJSON(w, http.StatusOK, &SCIMListResponse{
		Schemas:      []string{SCIMSchemaListResponse},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(groups),
		Resources:    resources,
	})
}

func (a *API) scimGetGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	groupID, err := uuid.FromString(chi.URLParam(r, "group_id"))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid group ID format")
	}

	group, err := models.FindSCIMGroupByID(db, groupID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMGroupNotFound, "Group not found")
		}
		return apierrors.NewInternalServerError("Error fetching group").WithInternalError(err)
	}

	if group.SSOProviderID != provider.ID {
		return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMGroupNotFound, "Group not found")
	}

	members, err := group.GetMembers(db)
	if err != nil {
		return apierrors.NewInternalServerError("Error fetching group members").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, a.groupToSCIMResponse(group, members))
}

func (a *API) scimCreateGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	var params SCIMGroupParams
	if err := a.parseSCIMBody(r, &params); err != nil {
		return err
	}
	if err := params.Validate(); err != nil {
		return err
	}

	var group *models.SCIMGroup
	terr := db.Transaction(func(tx *storage.Connection) error {
		if params.ExternalID != "" {
			existing, err := models.FindSCIMGroupByExternalID(tx, provider.ID, params.ExternalID)
			if err == nil && existing != nil {
				return apierrors.NewHTTPError(http.StatusConflict, apierrors.ErrorCodeSCIMGroupAlreadyExists, "Group with this externalId already exists")
			}
			if err != nil && !models.IsNotFoundError(err) {
				return apierrors.NewInternalServerError("Error checking existing group").WithInternalError(err)
			}
		}

		group = models.NewSCIMGroup(provider.ID, params.ExternalID, params.DisplayName)
		if err := tx.Create(group); err != nil {
			return apierrors.NewInternalServerError("Error creating group").WithInternalError(err)
		}

		for _, member := range params.Members {
			memberID, err := uuid.FromString(member.Value)
			if err != nil {
				continue
			}
			_ = group.AddMember(tx, memberID)
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	members, _ := group.GetMembers(db)
	return sendJSON(w, http.StatusCreated, a.groupToSCIMResponse(group, members))
}

func (a *API) scimReplaceGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	groupID, err := uuid.FromString(chi.URLParam(r, "group_id"))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid group ID format")
	}

	var params SCIMGroupParams
	if err := a.parseSCIMBody(r, &params); err != nil {
		return err
	}

	var group *models.SCIMGroup
	terr := db.Transaction(func(tx *storage.Connection) error {
		var err error
		group, err = models.FindSCIMGroupByID(tx, groupID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMGroupNotFound, "Group not found")
			}
			return apierrors.NewInternalServerError("Error fetching group").WithInternalError(err)
		}

		if group.SSOProviderID != provider.ID {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMGroupNotFound, "Group not found")
		}

		group.DisplayName = params.DisplayName
		if params.ExternalID != "" {
			group.ExternalID = params.ExternalID
		}

		if err := tx.Update(group); err != nil {
			return apierrors.NewInternalServerError("Error updating group").WithInternalError(err)
		}

		memberIDs := make([]uuid.UUID, 0, len(params.Members))
		for _, member := range params.Members {
			memberID, err := uuid.FromString(member.Value)
			if err != nil {
				continue
			}
			memberIDs = append(memberIDs, memberID)
		}

		return group.SetMembers(tx, memberIDs)
	})

	if terr != nil {
		return terr
	}

	members, _ := group.GetMembers(db)
	return sendJSON(w, http.StatusOK, a.groupToSCIMResponse(group, members))
}

func (a *API) scimPatchGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	groupID, err := uuid.FromString(chi.URLParam(r, "group_id"))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid group ID format")
	}

	var params SCIMPatchRequest
	if err := a.parseSCIMBody(r, &params); err != nil {
		return err
	}

	var group *models.SCIMGroup
	terr := db.Transaction(func(tx *storage.Connection) error {
		var err error
		group, err = models.FindSCIMGroupByID(tx, groupID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMGroupNotFound, "Group not found")
			}
			return apierrors.NewInternalServerError("Error fetching group").WithInternalError(err)
		}

		if group.SSOProviderID != provider.ID {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMGroupNotFound, "Group not found")
		}

		for _, op := range params.Operations {
			if err := a.applySCIMGroupPatch(tx, group, op); err != nil {
				return err
			}
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	members, _ := group.GetMembers(db)
	return sendJSON(w, http.StatusOK, a.groupToSCIMResponse(group, members))
}

func (a *API) applySCIMGroupPatch(tx *storage.Connection, group *models.SCIMGroup, op SCIMPatchOperation) error {
	switch strings.ToLower(op.Op) {
	case "add":
		if strings.ToLower(op.Path) == "members" || op.Path == "" {
			members, ok := op.Value.([]interface{})
			if !ok {
				return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "members must be an array")
			}
			for _, m := range members {
				memberMap, ok := m.(map[string]interface{})
				if !ok {
					continue
				}
				value, ok := memberMap["value"].(string)
				if !ok {
					continue
				}
				memberID, err := uuid.FromString(value)
				if err != nil {
					continue
				}
				_ = group.AddMember(tx, memberID)
			}
		}
	case "remove":
		if strings.HasPrefix(strings.ToLower(op.Path), "members") && strings.Contains(op.Path, "[") {
			start := strings.Index(op.Path, "\"")
			end := strings.LastIndex(op.Path, "\"")
			if start != -1 && end != -1 && start < end {
				value := op.Path[start+1 : end]
				memberID, err := uuid.FromString(value)
				if err != nil {
					return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid member ID in path")
				}
				return group.RemoveMember(tx, memberID)
			}
		}
	case "replace":
		switch strings.ToLower(op.Path) {
		case "displayname":
			displayName, ok := op.Value.(string)
			if !ok {
				return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "displayName must be a string")
			}
			group.DisplayName = displayName
			return tx.UpdateOnly(group, "display_name")
		case "members":
			members, ok := op.Value.([]interface{})
			if !ok {
				return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "members must be an array")
			}
			memberIDs := make([]uuid.UUID, 0, len(members))
			for _, m := range members {
				memberMap, ok := m.(map[string]interface{})
				if !ok {
					continue
				}
				value, ok := memberMap["value"].(string)
				if !ok {
					continue
				}
				memberID, err := uuid.FromString(value)
				if err != nil {
					continue
				}
				memberIDs = append(memberIDs, memberID)
			}
			return group.SetMembers(tx, memberIDs)
		}
	default:
		return apierrors.NewBadRequestError(apierrors.ErrorCodeSCIMMutuallyExclusive, "Unsupported patch operation: %s", op.Op)
	}
	return nil
}

func (a *API) scimDeleteGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	groupID, err := uuid.FromString(chi.URLParam(r, "group_id"))
	if err != nil {
		return apierrors.NewBadRequestError(apierrors.ErrorCodeValidationFailed, "Invalid group ID format")
	}

	terr := db.Transaction(func(tx *storage.Connection) error {
		group, err := models.FindSCIMGroupByID(tx, groupID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMGroupNotFound, "Group not found")
			}
			return apierrors.NewInternalServerError("Error fetching group").WithInternalError(err)
		}

		if group.SSOProviderID != provider.ID {
			return apierrors.NewNotFoundError(apierrors.ErrorCodeSCIMGroupNotFound, "Group not found")
		}

		return tx.Destroy(group)
	})

	if terr != nil {
		return terr
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// Service Provider Config Endpoints

func (a *API) scimServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	baseURL := a.getSCIMBaseURL()

	return sendJSON(w, http.StatusOK, map[string]interface{}{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://supabase.com/docs/guides/auth/enterprise-sso/scim",
		"patch":            map[string]interface{}{"supported": true},
		"bulk":             map[string]interface{}{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]interface{}{"supported": true, "maxResults": SCIMMaxPageSize},
		"changePassword":   map[string]interface{}{"supported": false},
		"sort":             map[string]interface{}{"supported": false},
		"etag":             map[string]interface{}{"supported": false},
		"authenticationSchemes": []map[string]interface{}{
			{
				"type":        "oauthbearertoken",
				"name":        "OAuth Bearer Token",
				"description": "Authentication scheme using the OAuth Bearer Token",
				"specUri":     "http://www.rfc-editor.org/info/rfc6750",
				"primary":     true,
			},
		},
		"meta": map[string]interface{}{
			"resourceType": "ServiceProviderConfig",
			"location":     baseURL + "/scim/v2/ServiceProviderConfig",
		},
	})
}

func (a *API) scimResourceTypes(w http.ResponseWriter, r *http.Request) error {
	baseURL := a.getSCIMBaseURL()

	return sendJSON(w, http.StatusOK, []map[string]interface{}{
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"endpoint":    "/Users",
			"description": "User Account",
			"schema":      SCIMSchemaUser,
			"meta":        map[string]interface{}{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/User"},
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "Group",
			"schema":      SCIMSchemaGroup,
			"meta":        map[string]interface{}{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/Group"},
		},
	})
}

func (a *API) scimSchemas(w http.ResponseWriter, r *http.Request) error {
	return sendJSON(w, http.StatusOK, []map[string]interface{}{
		{
			"id":          SCIMSchemaUser,
			"name":        "User",
			"description": "User Account",
			"attributes": []map[string]interface{}{
				{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
				{"name": "name", "type": "complex", "required": false},
				{"name": "emails", "type": "complex", "multiValued": true, "required": false},
				{"name": "active", "type": "boolean", "required": false},
				{"name": "externalId", "type": "string", "required": false},
			},
		},
		{
			"id":          SCIMSchemaGroup,
			"name":        "Group",
			"description": "Group",
			"attributes": []map[string]interface{}{
				{"name": "displayName", "type": "string", "required": true},
				{"name": "members", "type": "complex", "multiValued": true, "required": false},
				{"name": "externalId", "type": "string", "required": false},
			},
		},
	})
}
