package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid"
	filter "github.com/scim2/filter-parser/v2"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/utilities"
)

func (a *API) requireSCIMAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	token, err := a.extractBearerToken(r)
	if err != nil {
		return nil, apierrors.NewSCIMUnauthorizedError("Invalid or missing SCIM bearer token")
	}

	provider, err := models.FindSSOProviderBySCIMToken(db, token)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, apierrors.NewSCIMUnauthorizedError("Invalid SCIM bearer token")
		}
		return nil, apierrors.NewSCIMInternalServerError("Error validating SCIM token").WithInternalError(err)
	}

	if !provider.IsSCIMEnabled() {
		return nil, apierrors.NewSCIMForbiddenError("SCIM provisioning is not enabled for this provider")
	}

	if !provider.IsEnabled() {
		return nil, apierrors.NewSCIMForbiddenError("SSO provider is disabled")
	}

	return withSSOProvider(ctx, provider), nil
}

func (a *API) scimListUsers(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	startIndex, count := parseSCIMPagination(r)

	filterStr := r.URL.Query().Get("filter")
	filterClause, err := ParseSCIMFilterToSQL(filterStr, SCIMUserFilterAttrs)
	if err != nil {
		return err
	}

	providerType := "sso:" + provider.ID.String()

	users, totalResults, err := models.FindUsersByProviderWithFilter(db, providerType, filterClause, startIndex, count)
	if err != nil {
		return apierrors.NewSCIMInternalServerError("Error fetching users").WithInternalError(err)
	}

	resources := make([]interface{}, len(users))
	for i, user := range users {
		resources[i] = a.userToSCIMResponse(user, providerType)
	}

	return sendSCIMJSON(w, http.StatusOK, &SCIMListResponse{
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
		return apierrors.NewSCIMNotFoundError("User not found")
	}

	user, err := models.FindUserByID(db, userID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewSCIMNotFoundError("User not found")
		}
		return apierrors.NewSCIMInternalServerError("Error fetching user").WithInternalError(err)
	}

	if !models.UserBelongsToSSOProvider(user, provider.ID) {
		return apierrors.NewSCIMNotFoundError("User not found")
	}

	return sendSCIMJSON(w, http.StatusOK, a.userToSCIMResponse(user, "sso:"+provider.ID.String()))
}

func (a *API) scimCreateUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)
	config := a.config

	var params SCIMUserParams
	if err := a.parseSCIMBody(w, r, &params); err != nil {
		return err
	}
	if err := params.Validate(); err != nil {
		return err
	}

	var email string
	var emailType string
	if len(params.Emails) > 0 {
		for _, e := range params.Emails {
			if e.Primary {
				email = e.Value
				emailType = e.Type
				break
			}
		}
		if email == "" {
			email = params.Emails[0].Value
			emailType = params.Emails[0].Type
		}
	}

	if email == "" {
		return apierrors.NewSCIMBadRequestError("At least one email address is required", "invalidValue")
	}

	email, err := a.validateEmail(email)
	if err != nil {
		return apierrors.NewSCIMBadRequestError("Invalid email address", "invalidValue")
	}

	providerType := "sso:" + provider.ID.String()

	var user *models.User
	terr := db.Transaction(func(tx *storage.Connection) error {
		nonSSOUser, err := models.FindUserByEmailAndAudience(tx, email, config.JWT.Aud)
		if err != nil && !models.IsNotFoundError(err) {
			return apierrors.NewSCIMInternalServerError("Error checking existing user").WithInternalError(err)
		}
		if nonSSOUser != nil {
			return apierrors.NewSCIMConflictError("User with this email already exists", "uniqueness")
		}

		ssoUsers, err := models.FindSSOUsersByEmailAndProvider(tx, email, config.JWT.Aud, providerType)
		if err != nil {
			return apierrors.NewSCIMInternalServerError("Error checking existing SSO user").WithInternalError(err)
		}

		if len(ssoUsers) > 0 {
			var deprovisioned []*models.User
			for _, u := range ssoUsers {
				if u.BannedReason == nil || *u.BannedReason != scimDeprovisionedReason {
					return apierrors.NewSCIMConflictError("User with this email already exists", "uniqueness")
				}
				deprovisioned = append(deprovisioned, u)
			}

			if len(deprovisioned) > 1 {
				return apierrors.NewSCIMConflictError("Multiple deprovisioned users exist for this email", "uniqueness")
			}

			candidate := deprovisioned[0]

			if err := candidate.Ban(tx, 0, nil); err != nil {
				return apierrors.NewSCIMInternalServerError("Error reactivating user").WithInternalError(err)
			}

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
					candidate.UserMetaData = metadata
					if err := tx.UpdateOnly(candidate, "raw_user_meta_data"); err != nil {
						return apierrors.NewSCIMInternalServerError("Error updating user metadata").WithInternalError(err)
					}
				}
			}

			if email != candidate.GetEmail() {
				if err := candidate.SetEmail(tx, email); err != nil {
					return apierrors.NewSCIMInternalServerError("Error updating user email").WithInternalError(err)
				}
			}

			if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, candidate, models.UserModifiedAction, utilities.GetIPAddress(r), map[string]interface{}{
				"provider":        "scim",
				"sso_provider_id": provider.ID,
				"action":          "reactivated",
			}); terr != nil {
				return apierrors.NewSCIMInternalServerError("Error recording audit log entry").WithInternalError(terr)
			}
			user = candidate
			return nil
		}

		user, err = models.NewUser("", email, "", config.JWT.Aud, nil)
		if err != nil {
			return apierrors.NewSCIMInternalServerError("Error creating user").WithInternalError(err)
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
			if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
				return apierrors.NewSCIMConflictError("User with this email already exists", "uniqueness")
			}
			return apierrors.NewSCIMInternalServerError("Error saving user").WithInternalError(err)
		}

		identityID := params.ExternalID
		if identityID == "" {
			identityID = params.UserName
		}

		if _, err := a.createNewIdentity(tx, user, providerType, map[string]interface{}{
			"sub":         identityID,
			"external_id": params.ExternalID,
			"email":       email,
			"email_type":  emailType,
			"user_name":   params.UserName,
		}); err != nil {
			errToCheck := err
			if httpErr, ok := err.(*apierrors.HTTPError); ok && httpErr.InternalError != nil {
				errToCheck = httpErr.InternalError
			}
			if pgErr := utilities.NewPostgresError(errToCheck); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
				return apierrors.NewSCIMConflictError("User with this externalId already exists", "uniqueness")
			}
			return err
		}

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserSignedUpAction, utilities.GetIPAddress(r), map[string]interface{}{
			"provider":        "scim",
			"sso_provider_id": provider.ID,
		}); terr != nil {
			return apierrors.NewSCIMInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		if err := tx.Eager().Find(user, user.ID); err != nil {
			return apierrors.NewSCIMInternalServerError("Error reloading user").WithInternalError(err)
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	return sendSCIMJSON(w, http.StatusCreated, a.userToSCIMResponse(user, providerType))
}

func (a *API) scimReplaceUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)
	config := a.config

	userID, err := uuid.FromString(chi.URLParam(r, "user_id"))
	if err != nil {
		return apierrors.NewSCIMNotFoundError("User not found")
	}

	var params SCIMUserParams
	if err := a.parseSCIMBody(w, r, &params); err != nil {
		return err
	}
	if err := params.Validate(); err != nil {
		return err
	}

	// Extract primary email from params
	var email string
	if len(params.Emails) > 0 {
		for _, e := range params.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
		if email == "" {
			email = params.Emails[0].Value
		}
	}
	if email != "" {
		email, err = a.validateEmail(email)
		if err != nil {
			return apierrors.NewSCIMBadRequestError("Invalid email address", "invalidValue")
		}
	}

	var user *models.User
	terr := db.Transaction(func(tx *storage.Connection) error {
		var err error
		user, err = models.FindUserByID(tx, userID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewSCIMNotFoundError("User not found")
			}
			return apierrors.NewSCIMInternalServerError("Error fetching user").WithInternalError(err)
		}

		if !models.UserBelongsToSSOProvider(user, provider.ID) {
			return apierrors.NewSCIMNotFoundError("User not found")
		}

		metadata := user.UserMetaData
		if metadata == nil {
			metadata = make(map[string]interface{})
		}
		delete(metadata, "given_name")
		delete(metadata, "family_name")
		delete(metadata, "full_name")
		if params.Name != nil {
			if params.Name.GivenName != "" {
				metadata["given_name"] = params.Name.GivenName
			}
			if params.Name.FamilyName != "" {
				metadata["family_name"] = params.Name.FamilyName
			}
			if params.Name.Formatted != "" {
				metadata["full_name"] = params.Name.Formatted
			}
		}
		user.UserMetaData = metadata

		if params.Active != nil {
			if *params.Active {
				if err := user.Ban(tx, 0, nil); err != nil {
					return apierrors.NewSCIMInternalServerError("Error unbanning user").WithInternalError(err)
				}
			} else {
				if err := user.Ban(tx, time.Duration(math.MaxInt64), &scimDeprovisionedReason); err != nil {
					return apierrors.NewSCIMInternalServerError("Error banning user").WithInternalError(err)
				}
				if err := models.Logout(tx, user.ID); err != nil {
					return apierrors.NewSCIMInternalServerError("Error invalidating sessions").WithInternalError(err)
				}
			}
		}

		providerType := "sso:" + provider.ID.String()

		if email != "" && email != user.GetEmail() {
			if err := checkSCIMEmailUniqueness(tx, email, config.JWT.Aud, providerType, user.ID); err != nil {
				return err
			}
			if err := user.SetEmail(tx, email); err != nil {
				if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
					return apierrors.NewSCIMConflictError("Email already in use", "uniqueness")
				}
				return apierrors.NewSCIMInternalServerError("Error updating user email").WithInternalError(err)
			}
		}

		if err := tx.UpdateOnly(user, "raw_user_meta_data"); err != nil {
			return apierrors.NewSCIMInternalServerError("Error updating user").WithInternalError(err)
		}
		for i := range user.Identities {
			if user.Identities[i].Provider == providerType {
				if user.Identities[i].IdentityData == nil {
					user.Identities[i].IdentityData = make(map[string]interface{})
				}
				if params.UserName != "" {
					user.Identities[i].IdentityData["user_name"] = params.UserName
				}
				if email != "" {
					user.Identities[i].IdentityData["email"] = email
				}
				updateCols := []string{"identity_data"}
				if params.ExternalID != "" {
					user.Identities[i].ProviderID = params.ExternalID
					user.Identities[i].IdentityData["external_id"] = params.ExternalID
					updateCols = append(updateCols, "provider_id")
				} else {
					delete(user.Identities[i].IdentityData, "external_id")
				}
				if err := tx.UpdateOnly(&user.Identities[i], updateCols...); err != nil {
					if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
						return apierrors.NewSCIMConflictError("User with this externalId already exists", "uniqueness")
					}
					return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
				}
				break
			}
		}

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserModifiedAction, utilities.GetIPAddress(r), map[string]interface{}{
			"provider":        "scim",
			"sso_provider_id": provider.ID,
		}); terr != nil {
			return apierrors.NewSCIMInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		if err := tx.Eager().Find(user, user.ID); err != nil {
			return apierrors.NewSCIMInternalServerError("Error reloading user").WithInternalError(err)
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	return sendSCIMJSON(w, http.StatusOK, a.userToSCIMResponse(user, "sso:"+provider.ID.String()))
}

func (a *API) scimPatchUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)
	config := a.config

	userID, err := uuid.FromString(chi.URLParam(r, "user_id"))
	if err != nil {
		return apierrors.NewSCIMNotFoundError("User not found")
	}

	var params SCIMPatchRequest
	if err := a.parseSCIMBody(w, r, &params); err != nil {
		return err
	}
	if err := params.Validate(); err != nil {
		return err
	}

	var user *models.User
	terr := db.Transaction(func(tx *storage.Connection) error {
		var err error
		user, err = models.FindUserByID(tx, userID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewSCIMNotFoundError("User not found")
			}
			return apierrors.NewSCIMInternalServerError("Error fetching user").WithInternalError(err)
		}

		if !models.UserBelongsToSSOProvider(user, provider.ID) {
			return apierrors.NewSCIMNotFoundError("User not found")
		}

		for _, op := range params.Operations {
			if err := a.applySCIMUserPatch(tx, user, op, provider.ID); err != nil {
				return err
			}
		}

		if err := tx.Eager().Find(user, user.ID); err != nil {
			return apierrors.NewSCIMInternalServerError("Error reloading user").WithInternalError(err)
		}

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserModifiedAction, utilities.GetIPAddress(r), map[string]interface{}{
			"provider":        "scim",
			"sso_provider_id": provider.ID,
		}); terr != nil {
			return apierrors.NewSCIMInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	return sendSCIMJSON(w, http.StatusOK, a.userToSCIMResponse(user, "sso:"+provider.ID.String()))
}

func (a *API) applySCIMUserPatch(tx *storage.Connection, user *models.User, op SCIMPatchOperation, providerID uuid.UUID) error {
	providerType := "sso:" + providerID.String()

	var path *filter.Path
	if op.Path != "" {
		p, err := filter.ParsePath([]byte(op.Path))
		if err != nil {
			return apierrors.NewSCIMBadRequestError(
				fmt.Sprintf("Invalid path: %v", err), "invalidPath")
		}
		path = &p
	}

	switch strings.ToLower(op.Op) {
	case "remove":
		if path == nil {
			return apierrors.NewSCIMBadRequestError("remove operation requires a path", "noTarget")
		}
		attrName := strings.ToLower(path.AttributePath.AttributeName)
		if attrName == "externalid" {
			for i := range user.Identities {
				if user.Identities[i].Provider == providerType {
					if user.Identities[i].IdentityData != nil {
						delete(user.Identities[i].IdentityData, "external_id")
					}
					if err := tx.UpdateOnly(&user.Identities[i], "identity_data"); err != nil {
						return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
					}
					break
				}
			}
			return nil
		}
		return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Unsupported remove path: %s", op.Path), "invalidPath")

	case "add":
		if path != nil {
			attrName := strings.ToLower(path.AttributePath.AttributeName)
			if attrName == "externalid" {
				if externalID, ok := op.Value.(string); ok {
					for i := range user.Identities {
						if user.Identities[i].Provider == providerType {
							user.Identities[i].ProviderID = externalID
							if user.Identities[i].IdentityData == nil {
								user.Identities[i].IdentityData = make(map[string]interface{})
							}
							user.Identities[i].IdentityData["external_id"] = externalID
							if err := tx.UpdateOnly(&user.Identities[i], "provider_id", "identity_data"); err != nil {
								if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
									return apierrors.NewSCIMConflictError("User with this externalId already exists", "uniqueness")
								}
								return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
							}
							break
						}
					}
					return nil
				}
				return apierrors.NewSCIMBadRequestError("externalId must be a string", "invalidValue")
			}
			return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Unsupported add path: %s", op.Path), "invalidPath")
		}

		valueMap, ok := op.Value.(map[string]interface{})
		if !ok {
			return apierrors.NewSCIMBadRequestError("add operation without path requires an object value", "invalidValue")
		}
		for key, val := range valueMap {
			if key == "" {
				continue
			}
			keyPath, err := filter.ParsePath([]byte(key))
			if err != nil {
				return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid attribute path: %s", key), "invalidPath")
			}
			if strings.ToLower(keyPath.AttributePath.AttributeName) == "externalid" {
				if externalID, ok := val.(string); ok {
					for i := range user.Identities {
						if user.Identities[i].Provider == providerType {
							user.Identities[i].ProviderID = externalID
							if user.Identities[i].IdentityData == nil {
								user.Identities[i].IdentityData = make(map[string]interface{})
							}
							user.Identities[i].IdentityData["external_id"] = externalID
							if err := tx.UpdateOnly(&user.Identities[i], "provider_id", "identity_data"); err != nil {
								if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
									return apierrors.NewSCIMConflictError("User with this externalId already exists", "uniqueness")
								}
								return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
							}
							break
						}
					}
				}
			}
		}
		return nil

	case "replace":
		if path != nil {
			attrName := strings.ToLower(path.AttributePath.AttributeName)
			switch {
			case attrName == "active":
				active, ok := op.Value.(bool)
				if !ok {
					return apierrors.NewSCIMBadRequestError("active must be a boolean", "invalidValue")
				}
				if active {
					if err := user.Ban(tx, 0, nil); err != nil {
						return apierrors.NewSCIMInternalServerError("Error unbanning user").WithInternalError(err)
					}
					return nil
				}
				if err := user.Ban(tx, time.Duration(math.MaxInt64), &scimDeprovisionedReason); err != nil {
					return apierrors.NewSCIMInternalServerError("Error banning user").WithInternalError(err)
				}
				if err := models.Logout(tx, user.ID); err != nil {
					return apierrors.NewSCIMInternalServerError("Error invalidating sessions").WithInternalError(err)
				}
				return nil
			case attrName == "username":
				userName, ok := op.Value.(string)
				if !ok {
					return apierrors.NewSCIMBadRequestError("userName must be a string", "invalidValue")
				}
				for i := range user.Identities {
					if user.Identities[i].Provider == providerType {
						if user.Identities[i].IdentityData == nil {
							user.Identities[i].IdentityData = make(map[string]interface{})
						}
						user.Identities[i].IdentityData["user_name"] = userName
						if err := tx.UpdateOnly(&user.Identities[i], "identity_data"); err != nil {
							return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
						}
						break
					}
				}
				return nil
			case attrName == "emails" && path.ValueExpression != nil && strings.ToLower(path.SubAttributeName()) == "value":
				newEmail, ok := op.Value.(string)
				if !ok {
					return apierrors.NewSCIMBadRequestError("email value must be a string", "invalidValue")
				}
				validatedEmail, err := a.validateEmail(newEmail)
				if err != nil {
					return apierrors.NewSCIMBadRequestError("Invalid email address", "invalidValue")
				}
				if err := checkSCIMEmailUniqueness(tx, validatedEmail, a.config.JWT.Aud, providerType, user.ID); err != nil {
					return err
				}
				if err := user.SetEmail(tx, validatedEmail); err != nil {
					if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
						return apierrors.NewSCIMConflictError("Email already in use", "uniqueness")
					}
					return apierrors.NewSCIMInternalServerError("Error updating email").WithInternalError(err)
				}
				for i := range user.Identities {
					if user.Identities[i].Provider == providerType {
						if user.Identities[i].IdentityData == nil {
							user.Identities[i].IdentityData = make(map[string]interface{})
						}
						user.Identities[i].IdentityData["email"] = validatedEmail
						if err := tx.UpdateOnly(&user.Identities[i], "identity_data"); err != nil {
							return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
						}
						break
					}
				}
				return nil
			default:
				return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Unsupported replace path: %s", op.Path), "invalidPath")
			}
		}

		valueMap, ok := op.Value.(map[string]interface{})
		if !ok {
			return apierrors.NewSCIMBadRequestError("replace operation value must be an object when path is not specified", "invalidValue")
		}
		if user.UserMetaData == nil {
			user.UserMetaData = make(map[string]interface{})
		}
		metadataUpdated := false
		for key, val := range valueMap {
			if key == "" {
				continue
			}
			keyPath, err := filter.ParsePath([]byte(key))
			if err != nil {
				return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid attribute path: %s", key), "invalidPath")
			}
			attrName := strings.ToLower(keyPath.AttributePath.AttributeName)
			subAttr := strings.ToLower(keyPath.AttributePath.SubAttributeName())

			switch {
			case attrName == "username":
				if userName, ok := val.(string); ok && userName != "" {
					for i := range user.Identities {
						if user.Identities[i].Provider == providerType {
							if user.Identities[i].IdentityData == nil {
								user.Identities[i].IdentityData = make(map[string]interface{})
							}
							user.Identities[i].IdentityData["user_name"] = userName
							if err := tx.UpdateOnly(&user.Identities[i], "identity_data"); err != nil {
								return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
							}
							break
						}
					}
				}
			case attrName == "name" && subAttr == "formatted":
				if v, ok := val.(string); ok {
					user.UserMetaData["full_name"] = v
					metadataUpdated = true
				}
			case attrName == "name" && subAttr == "familyname":
				if v, ok := val.(string); ok {
					user.UserMetaData["family_name"] = v
					metadataUpdated = true
				}
			case attrName == "name" && subAttr == "givenname":
				if v, ok := val.(string); ok {
					user.UserMetaData["given_name"] = v
					metadataUpdated = true
				}
			case attrName == "externalid":
				if externalID, ok := val.(string); ok {
					for i := range user.Identities {
						if user.Identities[i].Provider == providerType {
							user.Identities[i].ProviderID = externalID
							if user.Identities[i].IdentityData == nil {
								user.Identities[i].IdentityData = make(map[string]interface{})
							}
							user.Identities[i].IdentityData["external_id"] = externalID
							if err := tx.UpdateOnly(&user.Identities[i], "provider_id", "identity_data"); err != nil {
								if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
									return apierrors.NewSCIMConflictError("User with this externalId already exists", "uniqueness")
								}
								return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
							}
							break
						}
					}
				}
			case attrName == "emails" && keyPath.ValueExpression != nil && strings.ToLower(keyPath.SubAttributeName()) == "value":
				if emailValue, ok := val.(string); ok {
					validatedEmail, err := a.validateEmail(emailValue)
					if err != nil {
						return apierrors.NewSCIMBadRequestError("Invalid email address", "invalidValue")
					}
					if err := checkSCIMEmailUniqueness(tx, validatedEmail, a.config.JWT.Aud, providerType, user.ID); err != nil {
						return err
					}
					if err := user.SetEmail(tx, validatedEmail); err != nil {
						if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
							return apierrors.NewSCIMConflictError("Email already in use", "uniqueness")
						}
						return apierrors.NewSCIMInternalServerError("Error updating email").WithInternalError(err)
					}
					for i := range user.Identities {
						if user.Identities[i].Provider == providerType {
							if user.Identities[i].IdentityData == nil {
								user.Identities[i].IdentityData = make(map[string]interface{})
							}
							user.Identities[i].IdentityData["email"] = validatedEmail
							if err := tx.UpdateOnly(&user.Identities[i], "identity_data"); err != nil {
								return apierrors.NewSCIMInternalServerError("Error updating identity").WithInternalError(err)
							}
							break
						}
					}
				}
			case attrName == "active":
				if active, ok := val.(bool); ok {
					if active {
						if err := user.Ban(tx, 0, nil); err != nil {
							return apierrors.NewSCIMInternalServerError("Error unbanning user").WithInternalError(err)
						}
					} else {
						if err := user.Ban(tx, time.Duration(math.MaxInt64), &scimDeprovisionedReason); err != nil {
							return apierrors.NewSCIMInternalServerError("Error banning user").WithInternalError(err)
						}
						if err := models.Logout(tx, user.ID); err != nil {
							return apierrors.NewSCIMInternalServerError("Error invalidating sessions").WithInternalError(err)
						}
					}
				}
			}
		}
		if metadataUpdated {
			if err := tx.UpdateOnly(user, "raw_user_meta_data"); err != nil {
				return apierrors.NewSCIMInternalServerError("Error updating user metadata").WithInternalError(err)
			}
		}

	default:
		return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Unsupported patch operation: %s", op.Op), "invalidSyntax")
	}
	return nil
}

func (a *API) scimDeleteUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)
	config := a.config

	userID, err := uuid.FromString(chi.URLParam(r, "user_id"))
	if err != nil {
		return apierrors.NewSCIMNotFoundError("User not found")
	}

	terr := db.Transaction(func(tx *storage.Connection) error {
		user, err := models.FindUserByID(tx, userID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewSCIMNotFoundError("User not found")
			}
			return apierrors.NewSCIMInternalServerError("Error fetching user").WithInternalError(err)
		}

		if !models.UserBelongsToSSOProvider(user, provider.ID) {
			return apierrors.NewSCIMNotFoundError("User not found")
		}

		// Already deprovisioned — return success for idempotent delete
		if user.IsBanned() && user.BannedReason != nil && *user.BannedReason == scimDeprovisionedReason {
			if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserDeletedAction, utilities.GetIPAddress(r), map[string]interface{}{
				"provider":        "scim",
				"sso_provider_id": provider.ID,
				"action":          "idempotent_delete",
			}); terr != nil {
				return apierrors.NewSCIMInternalServerError("Error recording audit log entry").WithInternalError(terr)
			}
			return nil
		}

		if err := user.Ban(tx, time.Duration(math.MaxInt64), &scimDeprovisionedReason); err != nil {
			return apierrors.NewSCIMInternalServerError("Error deprovisioning user").WithInternalError(err)
		}

		if terr := models.NewAuditLogEntry(config.AuditLog, r, tx, user, models.UserDeletedAction, utilities.GetIPAddress(r), map[string]interface{}{
			"provider":        "scim",
			"sso_provider_id": provider.ID,
		}); terr != nil {
			return apierrors.NewSCIMInternalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		if err := models.Logout(tx, user.ID); err != nil {
			return apierrors.NewSCIMInternalServerError("Error invalidating sessions").WithInternalError(err)
		}
		return nil
	})

	if terr != nil {
		return terr
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) scimListGroups(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	startIndex, count := parseSCIMPagination(r)

	filterStr := r.URL.Query().Get("filter")
	filterClause, err := ParseSCIMFilterToSQL(filterStr, SCIMGroupFilterAttrs)
	if err != nil {
		return err
	}

	groups, totalResults, err := models.FindSCIMGroupsBySSOProviderWithFilter(db, provider.ID, filterClause, startIndex, count)
	if err != nil {
		return apierrors.NewSCIMInternalServerError("Error fetching groups").WithInternalError(err)
	}

	excludeMembers := strings.Contains(strings.ToLower(r.URL.Query().Get("excludedAttributes")), "members")

	var membersByGroup map[uuid.UUID][]*models.User
	if !excludeMembers && len(groups) > 0 {
		groupIDs := make([]uuid.UUID, len(groups))
		for i, g := range groups {
			groupIDs[i] = g.ID
		}
		var err error
		membersByGroup, err = models.GetMembersForGroups(db, groupIDs)
		if err != nil {
			return apierrors.NewSCIMInternalServerError("Error fetching group members").WithInternalError(err)
		}
	}

	resources := make([]interface{}, len(groups))
	for i, group := range groups {
		var members []*models.User
		if !excludeMembers {
			members = membersByGroup[group.ID]
		}
		resources[i] = a.groupToSCIMResponse(group, members)
	}

	return sendSCIMJSON(w, http.StatusOK, &SCIMListResponse{
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
		return apierrors.NewSCIMNotFoundError("Group not found")
	}

	group, err := models.FindSCIMGroupByID(db, groupID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return apierrors.NewSCIMNotFoundError("Group not found")
		}
		return apierrors.NewSCIMInternalServerError("Error fetching group").WithInternalError(err)
	}

	if group.SSOProviderID != provider.ID {
		return apierrors.NewSCIMNotFoundError("Group not found")
	}

	excludeMembers := strings.Contains(strings.ToLower(r.URL.Query().Get("excludedAttributes")), "members")

	var members []*models.User
	if !excludeMembers {
		members, err = group.GetMembers(db)
		if err != nil {
			return apierrors.NewSCIMInternalServerError("Error fetching group members").WithInternalError(err)
		}
	}

	return sendSCIMJSON(w, http.StatusOK, a.groupToSCIMResponse(group, members))
}

func (a *API) scimCreateGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	var params SCIMGroupParams
	if err := a.parseSCIMBody(w, r, &params); err != nil {
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
				return apierrors.NewSCIMConflictError("Group with this externalId already exists", "uniqueness")
			}
			if err != nil && !models.IsNotFoundError(err) {
				return apierrors.NewSCIMInternalServerError("Error checking existing group").WithInternalError(err)
			}
		}

		group = models.NewSCIMGroup(provider.ID, params.ExternalID, params.DisplayName)
		if err := tx.Create(group); err != nil {
			if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
				return apierrors.NewSCIMConflictError("Group already exists", "uniqueness")
			}
			return apierrors.NewSCIMInternalServerError("Error creating group").WithInternalError(err)
		}

		if len(params.Members) > 0 {
			memberIDs := make([]uuid.UUID, 0, len(params.Members))
			for _, member := range params.Members {
				memberID, err := uuid.FromString(member.Value)
				if err != nil {
					return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid member ID: %s", member.Value), "invalidValue")
				}
				memberIDs = append(memberIDs, memberID)
			}
			if err := group.AddMembers(tx, memberIDs); err != nil {
				if _, ok := err.(models.UserNotFoundError); ok {
					return apierrors.NewSCIMNotFoundError("One or more members not found")
				}
				if _, ok := err.(models.UserNotInSSOProviderError); ok {
					return apierrors.NewSCIMBadRequestError("One or more members do not belong to this SSO provider", "invalidValue")
				}
				return apierrors.NewSCIMInternalServerError("Error adding group members").WithInternalError(err)
			}
		}

		return nil
	})

	if terr != nil {
		return terr
	}

	members, err := group.GetMembers(db)
	if err != nil {
		return apierrors.NewSCIMInternalServerError("Error fetching group members").WithInternalError(err)
	}
	return sendSCIMJSON(w, http.StatusCreated, a.groupToSCIMResponse(group, members))
}

func (a *API) scimReplaceGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	groupID, err := uuid.FromString(chi.URLParam(r, "group_id"))
	if err != nil {
		return apierrors.NewSCIMNotFoundError("Group not found")
	}

	var params SCIMGroupParams
	if err := a.parseSCIMBody(w, r, &params); err != nil {
		return err
	}
	if err := params.Validate(); err != nil {
		return err
	}

	var group *models.SCIMGroup
	terr := db.Transaction(func(tx *storage.Connection) error {
		var err error
		group, err = models.FindSCIMGroupByID(tx, groupID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewSCIMNotFoundError("Group not found")
			}
			return apierrors.NewSCIMInternalServerError("Error fetching group").WithInternalError(err)
		}

		if group.SSOProviderID != provider.ID {
			return apierrors.NewSCIMNotFoundError("Group not found")
		}

		group.DisplayName = params.DisplayName
		if params.ExternalID != "" {
			group.ExternalID = storage.NullString(params.ExternalID)
		} else {
			group.ExternalID = storage.NullString("")
		}

		if err := tx.Update(group); err != nil {
			if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
				return apierrors.NewSCIMConflictError("Group with this displayName already exists", "uniqueness")
			}
			return apierrors.NewSCIMInternalServerError("Error updating group").WithInternalError(err)
		}

		memberIDs := make([]uuid.UUID, 0, len(params.Members))
		for _, member := range params.Members {
			memberID, err := uuid.FromString(member.Value)
			if err != nil {
				return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid member ID: %s", member.Value), "invalidValue")
			}
			memberIDs = append(memberIDs, memberID)
		}

		if err := group.SetMembers(tx, memberIDs); err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewSCIMNotFoundError("One or more member IDs not found")
			}
			if _, ok := err.(models.UserNotInSSOProviderError); ok {
				return apierrors.NewSCIMBadRequestError("One or more members do not belong to this SSO provider", "invalidValue")
			}
			return apierrors.NewSCIMInternalServerError("Error setting group members").WithInternalError(err)
		}
		return nil
	})

	if terr != nil {
		return terr
	}

	group, err = models.FindSCIMGroupByID(db, groupID)
	if err != nil {
		return apierrors.NewSCIMInternalServerError("Error reloading group").WithInternalError(err)
	}

	members, err := group.GetMembers(db)
	if err != nil {
		return apierrors.NewSCIMInternalServerError("Error fetching group members").WithInternalError(err)
	}
	return sendSCIMJSON(w, http.StatusOK, a.groupToSCIMResponse(group, members))
}

func (a *API) scimPatchGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	groupID, err := uuid.FromString(chi.URLParam(r, "group_id"))
	if err != nil {
		return apierrors.NewSCIMNotFoundError("Group not found")
	}

	var params SCIMPatchRequest
	if err := a.parseSCIMBody(w, r, &params); err != nil {
		return err
	}
	if err := params.Validate(); err != nil {
		return err
	}

	var group *models.SCIMGroup
	terr := db.Transaction(func(tx *storage.Connection) error {
		var err error
		group, err = models.FindSCIMGroupByID(tx, groupID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewSCIMNotFoundError("Group not found")
			}
			return apierrors.NewSCIMInternalServerError("Error fetching group").WithInternalError(err)
		}

		if group.SSOProviderID != provider.ID {
			return apierrors.NewSCIMNotFoundError("Group not found")
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

	group, err = models.FindSCIMGroupByID(db, groupID)
	if err != nil {
		return apierrors.NewSCIMInternalServerError("Error reloading group").WithInternalError(err)
	}

	members, err := group.GetMembers(db)
	if err != nil {
		return apierrors.NewSCIMInternalServerError("Error fetching group members").WithInternalError(err)
	}
	return sendSCIMJSON(w, http.StatusOK, a.groupToSCIMResponse(group, members))
}

func (a *API) applySCIMGroupPatch(tx *storage.Connection, group *models.SCIMGroup, op SCIMPatchOperation) error {
	var path *filter.Path
	if op.Path != "" {
		p, err := filter.ParsePath([]byte(op.Path))
		if err != nil {
			return apierrors.NewSCIMBadRequestError(
				fmt.Sprintf("Invalid path: %v", err), "invalidPath")
		}
		path = &p
	}

	switch strings.ToLower(op.Op) {
	case "add":
		if path != nil {
			attrName := strings.ToLower(path.AttributePath.AttributeName)
			switch attrName {
			case "externalid":
				externalID, ok := op.Value.(string)
				if !ok {
					return apierrors.NewSCIMBadRequestError("externalId must be a string", "invalidValue")
				}
				group.ExternalID = storage.NullString(externalID)
				if err := tx.UpdateOnly(group, "external_id"); err != nil {
					if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
						return apierrors.NewSCIMConflictError("Group with this externalId already exists", "uniqueness")
					}
					return apierrors.NewSCIMInternalServerError("Error updating group external ID").WithInternalError(err)
				}
				return nil
			case "members":
				// fall through to member handling below
			default:
				return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Unsupported add path: %s", op.Path), "invalidPath")
			}
		}
		members, ok := op.Value.([]interface{})
		if !ok {
			return apierrors.NewSCIMBadRequestError("members must be an array", "invalidValue")
		}
		if len(members) > SCIMMaxMembers {
			return apierrors.NewSCIMRequestTooLargeError(fmt.Sprintf("Maximum %d members per operation", SCIMMaxMembers))
		}
		memberIDs := make([]uuid.UUID, 0, len(members))
		for _, m := range members {
			memberMap, ok := m.(map[string]interface{})
			if !ok {
				return apierrors.NewSCIMBadRequestError("Invalid member format", "invalidValue")
			}
			value, ok := memberMap["value"].(string)
			if !ok {
				return apierrors.NewSCIMBadRequestError("Member value must be a string", "invalidValue")
			}
			memberID, err := uuid.FromString(value)
			if err != nil {
				return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid member ID: %s", value), "invalidValue")
			}
			memberIDs = append(memberIDs, memberID)
		}
		if err := group.AddMembers(tx, memberIDs); err != nil {
			if _, ok := err.(models.UserNotFoundError); ok {
				return apierrors.NewSCIMNotFoundError("One or more members not found")
			}
			if _, ok := err.(models.UserNotInSSOProviderError); ok {
				return apierrors.NewSCIMBadRequestError("One or more members do not belong to this SSO provider", "invalidValue")
			}
			return apierrors.NewSCIMInternalServerError("Error adding group members").WithInternalError(err)
		}

	case "remove":
		if path == nil {
			return apierrors.NewSCIMBadRequestError("remove operation requires a path", "noTarget")
		}
		attrName := strings.ToLower(path.AttributePath.AttributeName)
		switch {
		case attrName == "externalid":
			group.ExternalID = storage.NullString("")
			if err := tx.UpdateOnly(group, "external_id"); err != nil {
				if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
					return apierrors.NewSCIMConflictError("Group with this externalId already exists", "uniqueness")
				}
				return apierrors.NewSCIMInternalServerError("Error updating group external ID").WithInternalError(err)
			}
			return nil
		case attrName == "members" && path.ValueExpression != nil:
			attrExpr, ok := path.ValueExpression.(*filter.AttributeExpression)
			if !ok || attrExpr.Operator != filter.EQ || strings.ToLower(attrExpr.AttributePath.AttributeName) != "value" {
				return apierrors.NewSCIMBadRequestError("Unsupported member filter", "invalidFilter")
			}
			memberIDStr, ok := attrExpr.CompareValue.(string)
			if !ok {
				return apierrors.NewSCIMBadRequestError("Member filter value must be a string", "invalidValue")
			}
			memberID, err := uuid.FromString(memberIDStr)
			if err != nil {
				return apierrors.NewSCIMBadRequestError("Invalid member ID in path", "invalidValue")
			}
			if err := group.RemoveMember(tx, memberID); err != nil {
				return apierrors.NewSCIMInternalServerError("Error removing group member").WithInternalError(err)
			}
			return nil
		default:
			return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Unsupported remove path: %s", op.Path), "invalidPath")
		}

	case "replace":
		if path != nil {
			attrName := strings.ToLower(path.AttributePath.AttributeName)
			switch attrName {
			case "externalid":
				externalID, ok := op.Value.(string)
				if !ok {
					return apierrors.NewSCIMBadRequestError("externalId must be a string", "invalidValue")
				}
				group.ExternalID = storage.NullString(externalID)
				if err := tx.UpdateOnly(group, "external_id"); err != nil {
					if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
						return apierrors.NewSCIMConflictError("Group with this externalId already exists", "uniqueness")
					}
					return apierrors.NewSCIMInternalServerError("Error updating group external ID").WithInternalError(err)
				}
				return nil
			case "displayname":
				displayName, ok := op.Value.(string)
				if !ok {
					return apierrors.NewSCIMBadRequestError("displayName must be a string", "invalidValue")
				}
				group.DisplayName = displayName
				if err := tx.UpdateOnly(group, "display_name"); err != nil {
					if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
						return apierrors.NewSCIMConflictError("Group with this displayName already exists", "uniqueness")
					}
					return apierrors.NewSCIMInternalServerError("Error updating group display name").WithInternalError(err)
				}
				return nil
			case "members":
				members, ok := op.Value.([]interface{})
				if !ok {
					return apierrors.NewSCIMBadRequestError("members must be an array", "invalidValue")
				}
				if len(members) > SCIMMaxMembers {
					return apierrors.NewSCIMRequestTooLargeError(fmt.Sprintf("Maximum %d members per operation", SCIMMaxMembers))
				}
				memberIDs := make([]uuid.UUID, 0, len(members))
				for _, m := range members {
					memberMap, ok := m.(map[string]interface{})
					if !ok {
						return apierrors.NewSCIMBadRequestError("Invalid member format", "invalidValue")
					}
					value, ok := memberMap["value"].(string)
					if !ok {
						return apierrors.NewSCIMBadRequestError("Member value must be a string", "invalidValue")
					}
					memberID, err := uuid.FromString(value)
					if err != nil {
						return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid member ID: %s", value), "invalidValue")
					}
					memberIDs = append(memberIDs, memberID)
				}
				if err := group.SetMembers(tx, memberIDs); err != nil {
					if models.IsNotFoundError(err) {
						return apierrors.NewSCIMNotFoundError("One or more member IDs not found")
					}
					if _, ok := err.(models.UserNotInSSOProviderError); ok {
						return apierrors.NewSCIMBadRequestError("One or more members do not belong to this SSO provider", "invalidValue")
					}
					return apierrors.NewSCIMInternalServerError("Error setting group members").WithInternalError(err)
				}
				return nil
			default:
				return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Unsupported replace path: %s", op.Path), "invalidPath")
			}
		}

		valueMap, ok := op.Value.(map[string]interface{})
		if !ok {
			return apierrors.NewSCIMBadRequestError("replace operation value must be an object when path is not specified", "invalidValue")
		}
		columnsToUpdate := []string{}
		for key, val := range valueMap {
			if key == "" {
				continue
			}
			keyPath, err := filter.ParsePath([]byte(key))
			if err != nil {
				return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Invalid attribute path: %s", key), "invalidPath")
			}
			switch strings.ToLower(keyPath.AttributePath.AttributeName) {
			case "externalid":
				if externalID, ok := val.(string); ok {
					group.ExternalID = storage.NullString(externalID)
					columnsToUpdate = append(columnsToUpdate, "external_id")
				}
			case "displayname":
				if displayName, ok := val.(string); ok {
					group.DisplayName = displayName
					columnsToUpdate = append(columnsToUpdate, "display_name")
				}
			}
		}
		if len(columnsToUpdate) > 0 {
			if err := tx.UpdateOnly(group, columnsToUpdate...); err != nil {
				if pgErr := utilities.NewPostgresError(err); pgErr != nil && pgErr.IsUniqueConstraintViolated() {
					return apierrors.NewSCIMConflictError("Group already exists with this value", "uniqueness")
				}
				return apierrors.NewSCIMInternalServerError("Error updating group").WithInternalError(err)
			}
		}

	default:
		return apierrors.NewSCIMBadRequestError(fmt.Sprintf("Unsupported patch operation: %s", op.Op), "invalidSyntax")
	}
	return nil
}

func (a *API) scimDeleteGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	provider := getSSOProvider(ctx)

	groupID, err := uuid.FromString(chi.URLParam(r, "group_id"))
	if err != nil {
		return apierrors.NewSCIMNotFoundError("Group not found")
	}

	terr := db.Transaction(func(tx *storage.Connection) error {
		group, err := models.FindSCIMGroupByID(tx, groupID)
		if err != nil {
			if models.IsNotFoundError(err) {
				return apierrors.NewSCIMNotFoundError("Group not found")
			}
			return apierrors.NewSCIMInternalServerError("Error fetching group").WithInternalError(err)
		}

		if group.SSOProviderID != provider.ID {
			return apierrors.NewSCIMNotFoundError("Group not found")
		}

		if err := tx.Destroy(group); err != nil {
			return apierrors.NewSCIMInternalServerError("Error deleting group").WithInternalError(err)
		}
		return nil
	})

	if terr != nil {
		return terr
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) scimServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	baseURL := a.getSCIMBaseURL()

	return sendSCIMJSON(w, http.StatusOK, map[string]interface{}{
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

	resourceTypes := []interface{}{
		map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"endpoint":    "/Users",
			"description": "User Account",
			"schema":      SCIMSchemaUser,
			"meta":        map[string]interface{}{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/User"},
		},
		map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "Group",
			"schema":      SCIMSchemaGroup,
			"meta":        map[string]interface{}{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/Group"},
		},
	}

	return sendSCIMJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{SCIMSchemaListResponse},
		TotalResults: len(resourceTypes),
		StartIndex:   1,
		ItemsPerPage: len(resourceTypes),
		Resources:    resourceTypes,
	})
}

func (a *API) scimSchemas(w http.ResponseWriter, r *http.Request) error {
	baseURL := a.getSCIMBaseURL()
	schemas := []interface{}{
		map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":          SCIMSchemaUser,
			"name":        "User",
			"description": "User Account",
			"attributes": []map[string]interface{}{
				{"name": "userName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
				{"name": "name", "type": "complex", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none", "subAttributes": []map[string]interface{}{
					{"name": "formatted", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
					{"name": "familyName", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
					{"name": "givenName", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				}},
				{"name": "emails", "type": "complex", "multiValued": true, "required": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none", "subAttributes": []map[string]interface{}{
					{"name": "value", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
					{"name": "type", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
					{"name": "primary", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				}},
				{"name": "active", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
			},
			"meta": map[string]interface{}{
				"resourceType": "Schema",
				"location":     baseURL + "/scim/v2/Schemas/" + SCIMSchemaUser,
			},
		},
		map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":          SCIMSchemaGroup,
			"name":        "Group",
			"description": "Group",
			"attributes": []map[string]interface{}{
				{"name": "displayName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none", "subAttributes": []map[string]interface{}{
					{"name": "value", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "immutable", "returned": "default", "uniqueness": "none"},
					{"name": "$ref", "type": "reference", "multiValued": false, "required": false, "caseExact": false, "mutability": "immutable", "returned": "default", "uniqueness": "none", "referenceTypes": []string{"User"}},
					{"name": "display", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readOnly", "returned": "default", "uniqueness": "none"},
				}},
				{"name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
			},
			"meta": map[string]interface{}{
				"resourceType": "Schema",
				"location":     baseURL + "/scim/v2/Schemas/" + SCIMSchemaGroup,
			},
		},
	}

	return sendSCIMJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{SCIMSchemaListResponse},
		TotalResults: len(schemas),
		StartIndex:   1,
		ItemsPerPage: len(schemas),
		Resources:    schemas,
	})
}

func (a *API) scimResourceTypeByID(w http.ResponseWriter, r *http.Request) error {
	resourceTypeID := chi.URLParam(r, "resource_type_id")
	baseURL := a.getSCIMBaseURL()

	var resourceType map[string]interface{}

	switch resourceTypeID {
	case "User":
		resourceType = map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "User",
			"name":        "User",
			"endpoint":    "/Users",
			"description": "User Account",
			"schema":      SCIMSchemaUser,
			"meta":        map[string]interface{}{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/User"},
		}
	case "Group":
		resourceType = map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "Group",
			"schema":      SCIMSchemaGroup,
			"meta":        map[string]interface{}{"resourceType": "ResourceType", "location": baseURL + "/scim/v2/ResourceTypes/Group"},
		}
	default:
		return sendSCIMError(w, http.StatusNotFound, "Resource type not found", "")
	}

	return sendSCIMJSON(w, http.StatusOK, resourceType)
}

func (a *API) scimSchemaByID(w http.ResponseWriter, r *http.Request) error {
	schemaID := chi.URLParam(r, "schema_id")
	baseURL := a.getSCIMBaseURL()

	var schema map[string]interface{}

	switch schemaID {
	case SCIMSchemaUser:
		schema = map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":          SCIMSchemaUser,
			"name":        "User",
			"description": "User Account",
			"attributes": []map[string]interface{}{
				{"name": "userName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
				{"name": "name", "type": "complex", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none", "subAttributes": []map[string]interface{}{
					{"name": "formatted", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
					{"name": "familyName", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
					{"name": "givenName", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				}},
				{"name": "emails", "type": "complex", "multiValued": true, "required": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none", "subAttributes": []map[string]interface{}{
					{"name": "value", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
					{"name": "type", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
					{"name": "primary", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				}},
				{"name": "active", "type": "boolean", "multiValued": false, "required": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
			},
			"meta": map[string]interface{}{
				"resourceType": "Schema",
				"location":     baseURL + "/scim/v2/Schemas/" + SCIMSchemaUser,
			},
		}
	case SCIMSchemaGroup:
		schema = map[string]interface{}{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":          SCIMSchemaGroup,
			"name":        "Group",
			"description": "Group",
			"attributes": []map[string]interface{}{
				{"name": "displayName", "type": "string", "multiValued": false, "required": true, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none", "subAttributes": []map[string]interface{}{
					{"name": "value", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "immutable", "returned": "default", "uniqueness": "none"},
					{"name": "$ref", "type": "reference", "multiValued": false, "required": false, "caseExact": false, "mutability": "immutable", "returned": "default", "uniqueness": "none", "referenceTypes": []string{"User"}},
					{"name": "display", "type": "string", "multiValued": false, "required": false, "caseExact": false, "mutability": "readOnly", "returned": "default", "uniqueness": "none"},
				}},
				{"name": "externalId", "type": "string", "multiValued": false, "required": false, "caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
			},
			"meta": map[string]interface{}{
				"resourceType": "Schema",
				"location":     baseURL + "/scim/v2/Schemas/" + SCIMSchemaGroup,
			},
		}
	default:
		return sendSCIMError(w, http.StatusNotFound, "Schema not found", "")
	}

	return sendSCIMJSON(w, http.StatusOK, schema)
}

func sendSCIMError(w http.ResponseWriter, status int, detail string, scimType string) error {
	return sendSCIMJSON(w, status, apierrors.NewSCIMHTTPError(status, detail, scimType))
}

func (a *API) scimNotFound(w http.ResponseWriter, r *http.Request) error {
	return sendSCIMError(w, http.StatusNotFound, "Resource not found", "")
}
