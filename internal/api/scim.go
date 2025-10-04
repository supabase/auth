package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// SCIM response structures

type SCIMServiceProviderConfig struct {
	Schemas               []string      `json:"schemas"`
	Patch                 SCIMSupported `json:"patch"`
	Bulk                  SCIMSupported `json:"bulk"`
	Filter                SCIMFilter    `json:"filter"`
	ChangePassword        SCIMSupported `json:"changePassword"`
	Sort                  SCIMSupported `json:"sort"`
	Etag                  SCIMSupported `json:"etag"`
	AuthenticationSchemes []interface{} `json:"authenticationSchemes"`
}

type SCIMSupported struct {
	Supported bool `json:"supported"`
}

type SCIMFilter struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

type SCIMResourceType struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Schema   string `json:"schema"`
}

type SCIMResourceTypesResponse struct {
	Resources    []SCIMResourceType `json:"Resources"`
	TotalResults int                `json:"totalResults"`
	ItemsPerPage int                `json:"itemsPerPage"`
	StartIndex   int                `json:"startIndex"`
	Schemas      []string           `json:"schemas"`
}

type SCIMSchemaAttribute struct {
	Name          string                `json:"name"`
	Type          string                `json:"type"`
	Required      *bool                 `json:"required,omitempty"`
	Uniqueness    *string               `json:"uniqueness,omitempty"`
	SubAttributes []SCIMSchemaAttribute `json:"subAttributes,omitempty"`
}

type SCIMSchema struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Attributes  []SCIMSchemaAttribute `json:"attributes"`
}

type SCIMSchemasResponse struct {
	Resources    []SCIMSchema `json:"Resources"`
	TotalResults int          `json:"totalResults"`
	ItemsPerPage int          `json:"itemsPerPage"`
	StartIndex   int          `json:"startIndex"`
	Schemas      []string     `json:"schemas"`
}

// ServiceProviderConfig
func (a *API) SCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	resp := SCIMServiceProviderConfig{
		Schemas:               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		Patch:                 SCIMSupported{Supported: true},
		Bulk:                  SCIMSupported{Supported: false},
		Filter:                SCIMFilter{Supported: true, MaxResults: 200},
		ChangePassword:        SCIMSupported{Supported: false},
		Sort:                  SCIMSupported{Supported: false},
		Etag:                  SCIMSupported{Supported: false},
		AuthenticationSchemes: []interface{}{},
	}
	return scimSendJSON(w, http.StatusOK, resp)
}

// ResourceTypes
func (a *API) SCIMResourceTypes(w http.ResponseWriter, r *http.Request) error {
	resp := SCIMResourceTypesResponse{
		Resources: []SCIMResourceType{
			{
				ID:       "User",
				Name:     "User",
				Endpoint: "/scim/v2/Users",
				Schema:   "urn:ietf:params:scim:schemas:core:2.0:User",
			},
		},
		TotalResults: 1,
		ItemsPerPage: 1,
		StartIndex:   1,
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
	}
	return scimSendJSON(w, http.StatusOK, resp)
}

// Schemas (return only core User schema minimal)
func (a *API) SCIMSchemas(w http.ResponseWriter, r *http.Request) error {
	required := true
	uniqueness := "server"

	resp := SCIMSchemasResponse{
		Resources: []SCIMSchema{
			{
				ID:          "urn:ietf:params:scim:schemas:core:2.0:User",
				Name:        "User",
				Description: "User Account",
				Attributes: []SCIMSchemaAttribute{
					{Name: "userName", Type: "string", Required: &required, Uniqueness: &uniqueness},
					{Name: "externalId", Type: "string"},
					{Name: "active", Type: "boolean"},
					{Name: "displayName", Type: "string"},
					{Name: "name", Type: "complex", SubAttributes: []SCIMSchemaAttribute{
						{Name: "givenName", Type: "string"},
						{Name: "familyName", Type: "string"},
					}},
					{Name: "emails", Type: "complex"},
				},
			},
		},
		TotalResults: 1,
		ItemsPerPage: 1,
		StartIndex:   1,
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
	}
	return scimSendJSON(w, http.StatusOK, resp)
}

// Users list
func (a *API) SCIMUsersList(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.scimAudience()

	// SCIM pagination uses 1-based startIndex
	startIndex, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if startIndex <= 0 {
		startIndex = 1
	}
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if count <= 0 || count > 200 {
		count = 50
	}
	page := (startIndex-1)/count + 1

	filter := r.URL.Query().Get("filter")

	var resources []any
	var total uint64

	if filter != "" {
		// minimal parser: "attr eq \"value\""
		parts := strings.Split(filter, "eq")
		if len(parts) == 2 {
			attr := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			// Parse JSON string to handle proper escaping
			var parsedVal string
			if err := json.Unmarshal([]byte(val), &parsedVal); err != nil {
				// Fallback to simple trim if JSON parsing fails
				parsedVal = strings.Trim(val, "\"")
			}
			val = parsedVal

			switch attr {
			case "userName":
				providerID := getSCIMProvider(ctx)
				var user *models.User
				q := db.Q().Where("instance_id = ? and aud = ? and email = ? and scim_provider_id = ?", uuid.Nil, aud, val, providerID)
				err := q.First(&user)
				if err == nil && user != nil {
					resources = append(resources, a.toSCIMUser(user))
					total = 1
				} else {
					total = 0
				}
			case "externalId":
				var users []*models.User
				providerID := getSCIMProvider(ctx)
				q := db.Q().Where("instance_id = ? and aud = ? and scim_external_id = ? and scim_provider_id = ?", uuid.Nil, aud, val, providerID)
				if err := q.All(&users); err == nil {
					for _, u := range users {
						resources = append(resources, a.toSCIMUser(u))
					}
					total = uint64(len(users))
				}
			}
		}
		if resources == nil {
			resources = []any{}
		}
		resp := map[string]any{
			"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
			"totalResults": total,
			"itemsPerPage": len(resources),
			"startIndex":   1,
			"Resources":    resources,
		}
		return scimSendJSON(w, http.StatusOK, resp)
	}

	// Ensure page and count are non-negative before converting to uint64
	if page < 0 {
		page = 1
	}
	if count < 0 {
		count = 50
	}
	pageParams := &models.Pagination{Page: uint64(page), PerPage: uint64(count)} // #nosec G115

	// Filter by provider ID for isolation
	providerID := getSCIMProvider(ctx)
	var users []*models.User
	q := db.Q().Where("instance_id = ? and aud = ? and scim_provider_id = ?", uuid.Nil, aud, providerID)
	q = q.Paginate(int(pageParams.Page), int(pageParams.PerPage)) // #nosec G115
	err := q.All(&users)
	if err != nil {
		return err
	}

	resources = make([]any, 0, len(users))
	for _, u := range users {
		resources = append(resources, a.toSCIMUser(u))
	}

	// Get total count for the provider
	var totalCount int
	countQ := db.Q().Where("instance_id = ? and aud = ? and scim_provider_id = ?", uuid.Nil, aud, providerID)
	totalCount, _ = countQ.Count(&models.User{})

	resp := map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": totalCount,
		"itemsPerPage": len(resources),
		"startIndex":   startIndex,
		"Resources":    resources,
	}
	return scimSendJSON(w, http.StatusOK, resp)
}

// Users get
func (a *API) SCIMUsersGet(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	idStr := chi.URLParam(r, "scim_user_id")
	userID, err := uuid.FromString(idStr)
	if err != nil {
		return SCIMNotFound("User not found")
	}
	u, err := models.FindUserByID(db, userID)
	if err != nil {
		return SCIMNotFound("User not found")
	}
	if u.Aud != a.scimAudience() {
		return SCIMNotFound("User not found")
	}

	// Check provider isolation
	providerID := getSCIMProvider(ctx)
	if len(u.SCIMProviderID) > 0 && u.SCIMProviderID.String() != providerID {
		return SCIMNotFound("User not found")
	}
	return scimSendJSON(w, http.StatusOK, a.toSCIMUser(u))
}

// Users create
func (a *API) SCIMUsersCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return err
	}

	aud := a.scimAudience()
	email := getString(body, "userName")
	if email == "" {
		// fallback from emails[0].value
		if emails, ok := body["emails"].([]any); ok && len(emails) > 0 {
			if m, ok := emails[0].(map[string]any); ok {
				email = getString(m, "value")
			}
		}
	}

	user, err := models.NewUser("", email, "", aud, map[string]any{})
	if err != nil {
		return err
	}

	// metadata
	if name, ok := body["name"].(map[string]any); ok {
		if user.UserMetaData == nil {
			user.UserMetaData = map[string]any{}
		}
		if v := getString(name, "givenName"); v != "" {
			user.UserMetaData["given_name"] = v
		}
		if v := getString(name, "familyName"); v != "" {
			user.UserMetaData["family_name"] = v
		}
	}
	if v := getString(body, "displayName"); v != "" {
		if user.UserMetaData == nil {
			user.UserMetaData = map[string]any{}
		}
		user.UserMetaData["display_name"] = v
	}
	if v := getString(body, "externalId"); v != "" {
		user.SCIMExternalID = storage.NullString(v)
	}

	// Set provider ID for isolation
	providerID := getSCIMProvider(ctx)
	user.SCIMProviderID = storage.NullString(providerID)

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := tx.Create(user); terr != nil {
			return terr
		}
		if user.GetEmail() != "" {
			if _, terr := a.createNewIdentity(tx, user, "email", map[string]any{"email": user.GetEmail(), "email_verified": true, "sub": user.ID.String()}); terr != nil {
				return terr
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	w.Header().Set("Location", a.scimUserLocation(user.ID))
	return scimSendJSON(w, http.StatusCreated, a.toSCIMUser(user))
}

// Users replace
func (a *API) SCIMUsersReplace(w http.ResponseWriter, r *http.Request) error {
	// For minimal impl, treat as PATCH replace of active/displayName/name
	return a.SCIMUsersPatch(w, r)
}

// Users patch
func (a *API) SCIMUsersPatch(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	idStr := chi.URLParam(r, "scim_user_id")
	userID, err := uuid.FromString(idStr)
	if err != nil {
		return SCIMNotFound("User not found")
	}
	user, err := models.FindUserByID(db, userID)
	if err != nil {
		return SCIMNotFound("User not found")
	}
	if user.Aud != a.scimAudience() {
		return SCIMNotFound("User not found")
	}

	// Check provider isolation
	providerID := getSCIMProvider(ctx)
	if len(user.SCIMProviderID) > 0 && user.SCIMProviderID.String() != providerID {
		return SCIMNotFound("User not found")
	}

	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return err
	}

	// Support RFC7644 patch operations minimally
	if ops, ok := body["Operations"].([]any); ok {
		err = db.Transaction(func(tx *storage.Connection) error {
			for _, op := range ops {
				m, _ := op.(map[string]any)
				path := getString(m, "path")
				// normalize path
				switch path {
				case "active", "path eq \"active\"":
					val, _ := m["value"].(bool)
					if val {
						// restore by un-banning
						user.BannedUntil = nil
						if terr := user.UpdateBannedUntil(tx); terr != nil {
							return terr
						}
					} else {
						// ban for 100 years
						t := time.Now().Add(100 * 365 * 24 * time.Hour)
						user.BannedUntil = &t
						if terr := user.UpdateBannedUntil(tx); terr != nil {
							return terr
						}
					}
				case "name.givenName":
					if user.UserMetaData == nil {
						user.UserMetaData = map[string]any{}
					}
					user.UserMetaData["given_name"] = getString(m, "value")
					if terr := user.UpdateUserMetaData(tx, user.UserMetaData); terr != nil {
						return terr
					}
				case "name.familyName":
					if user.UserMetaData == nil {
						user.UserMetaData = map[string]any{}
					}
					user.UserMetaData["family_name"] = getString(m, "value")
					if terr := user.UpdateUserMetaData(tx, user.UserMetaData); terr != nil {
						return terr
					}
				case "displayName":
					if user.UserMetaData == nil {
						user.UserMetaData = map[string]any{}
					}
					user.UserMetaData["display_name"] = getString(m, "value")
					if terr := user.UpdateUserMetaData(tx, user.UserMetaData); terr != nil {
						return terr
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return scimSendJSON(w, http.StatusOK, a.toSCIMUser(user))
}

// Users delete (deprovision)
func (a *API) SCIMUsersDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	idStr := chi.URLParam(r, "scim_user_id")
	userID, err := uuid.FromString(idStr)
	if err != nil {
		return SCIMNotFound("User not found")
	}
	user, err := models.FindUserByID(db, userID)
	if err != nil {
		return SCIMNotFound("User not found")
	}
	if user.Aud != a.scimAudience() {
		return SCIMNotFound("User not found")
	}

	// Check provider isolation
	providerID := getSCIMProvider(ctx)
	if len(user.SCIMProviderID) > 0 && user.SCIMProviderID.String() != providerID {
		return SCIMNotFound("User not found")
	}

	if a.config.SCIM.BanOnDeactivate {
		// ban long-term
		t := time.Now().Add(100 * 365 * 24 * time.Hour)
		user.BannedUntil = &t
		if terr := user.UpdateBannedUntil(db); terr != nil {
			return terr
		}
	} else {
		// soft delete user and identities
		if err := db.Transaction(func(tx *storage.Connection) error {
			if terr := user.SoftDeleteUser(tx); terr != nil {
				return terr
			}
			if terr := user.SoftDeleteUserIdentities(tx); terr != nil {
				return terr
			}
			return nil
		}); err != nil {
			return err
		}
	}

	return scimSendJSON(w, http.StatusNoContent, nil)
}

func (a *API) toSCIMUser(u *models.User) map[string]any {
	baseURL := a.config.SCIM.BaseURL
	if baseURL == "" {
		baseURL = a.config.API.ExternalURL
	}
	emails := []any{}
	if u.GetEmail() != "" {
		emails = append(emails, map[string]any{"value": u.GetEmail(), "primary": true})
	}
	active := !u.IsBanned() && u.DeletedAt == nil
	return map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":      u.ID.String(),
		"externalId": func() any {
			if len(u.SCIMExternalID) > 0 {
				return u.SCIMExternalID.String()
			}
			return nil
		}(),
		"userName": u.GetEmail(),
		"displayName": func() any {
			if v, ok := u.UserMetaData["display_name"]; ok {
				return v
			}
			return nil
		}(),
		"name": map[string]any{
			"givenName":  u.UserMetaData["given_name"],
			"familyName": u.UserMetaData["family_name"],
		},
		"active": active,
		"emails": emails,
		"meta": map[string]any{
			"resourceType": "User",
			"location":     baseURL + "/scim/v2/Users/" + u.ID.String(),
			"created":      u.CreatedAt.Format(time.RFC3339),
			"lastModified": u.UpdatedAt.Format(time.RFC3339),
		},
	}
}

func scimSendJSON(w http.ResponseWriter, status int, obj any) error {
	w.Header().Set("Content-Type", "application/scim+json")
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	w.WriteHeader(status)
	_, err = w.Write(b)
	return err
}

func (a *API) scimUserLocation(id uuid.UUID) string {
	baseURL := a.config.SCIM.BaseURL
	if baseURL == "" {
		baseURL = a.config.API.ExternalURL
	}
	return baseURL + "/scim/v2/Users/" + id.String()
}

func getString(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// scimAudience returns a single audience context for SCIM operations.
// SCIM tokens are operator-level and should not be able to enumerate across audiences.
func (a *API) scimAudience() string {
	if a.config.SCIM.DefaultAudience != "" {
		return a.config.SCIM.DefaultAudience
	}
	return a.config.JWT.Aud
}
