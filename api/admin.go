package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/observability"
	"github.com/netlify/gotrue/storage"
	"github.com/sethvargo/go-password/password"
)

type AdminUserParams struct {
	Aud          string                 `json:"aud"`
	Role         string                 `json:"role"`
	Email        string                 `json:"email"`
	Phone        string                 `json:"phone"`
	Password     *string                `json:"password"`
	EmailConfirm bool                   `json:"email_confirm"`
	PhoneConfirm bool                   `json:"phone_confirm"`
	UserMetaData map[string]interface{} `json:"user_metadata"`
	AppMetaData  map[string]interface{} `json:"app_metadata"`
	BanDuration  string                 `json:"ban_duration"`
}

type adminUserUpdateFactorParams struct {
	FriendlyName string `json:"friendly_name"`
	FactorType   string `json:"factor_type"`
}

type AdminListUsersResponse struct {
	Users []*models.User `json:"users"`
	Aud   string         `json:"aud"`
}

func (a *API) loadUser(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	db := a.db.WithContext(ctx)

	userID, err := uuid.FromString(chi.URLParam(r, "user_id"))
	if err != nil {
		return nil, badRequestError("user_id must be an UUID")
	}

	observability.LogEntrySetField(r, "user_id", userID)

	u, err := models.FindUserByID(db, userID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError("User not found")
		}
		return nil, internalServerError("Database error loading user").WithInternalError(err)
	}

	return withUser(ctx, u), nil
}

func (a *API) loadFactor(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	factorID, err := uuid.FromString(chi.URLParam(r, "factor_id"))
	if err != nil {
		return nil, badRequestError("factor_id must be an UUID")
	}

	observability.LogEntrySetField(r, "factor_id", factorID)

	f, err := models.FindFactorByFactorID(a.db, factorID)
	if err != nil {
		if models.IsNotFoundError(err) {
			return nil, notFoundError("Factor not found")
		}
		return nil, internalServerError("Database error loading factor").WithInternalError(err)
	}
	return withFactor(r.Context(), f), nil
}

func (a *API) getAdminParams(r *http.Request) (*AdminUserParams, error) {
	params := AdminUserParams{}

	body, err := getBodyBytes(r)
	if err != nil {
		return nil, badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, &params); err != nil {
		return nil, badRequestError("Could not decode admin user params: %v", err)
	}

	return &params, nil
}

// adminUsers responds with a list of all users in a given audience
func (a *API) adminUsers(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	aud := a.requestAud(ctx, r)

	pageParams, err := paginate(r)
	if err != nil {
		return badRequestError("Bad Pagination Parameters: %v", err)
	}

	sortParams, err := sort(r, map[string]bool{models.CreatedAt: true}, []models.SortField{{Name: models.CreatedAt, Dir: models.Descending}})
	if err != nil {
		return badRequestError("Bad Sort Parameters: %v", err)
	}

	filter := r.URL.Query().Get("filter")

	users, err := models.FindUsersInAudience(db, aud, pageParams, sortParams, filter)
	if err != nil {
		return internalServerError("Database error finding users").WithInternalError(err)
	}
	addPaginationHeaders(w, r, pageParams)

	return sendJSON(w, http.StatusOK, AdminListUsersResponse{
		Users: users,
		Aud:   aud,
	})
}

// adminUserGet returns information about a single user
func (a *API) adminUserGet(w http.ResponseWriter, r *http.Request) error {
	user := getUser(r.Context())

	return sendJSON(w, http.StatusOK, user)
}

// adminUserUpdate updates a single user object
func (a *API) adminUserUpdate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	user := getUser(ctx)
	adminUser := getAdminUser(ctx)
	params, err := a.getAdminParams(r)
	config := a.config
	if err != nil {
		return err
	}

	if params.Email != "" {
		params.Email, err = a.validateEmail(ctx, params.Email)
		if err != nil {
			return err
		}
	}

	if params.Phone != "" {
		params.Phone, err = a.validatePhone(params.Phone)
		if err != nil {
			return err
		}
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if params.Role != "" {
			if terr := user.SetRole(tx, params.Role); terr != nil {
				return terr
			}
		}

		if params.EmailConfirm {
			if terr := user.Confirm(tx); terr != nil {
				return terr
			}
		}

		if params.PhoneConfirm {
			if terr := user.ConfirmPhone(tx); terr != nil {
				return terr
			}
		}

		if params.Password != nil {
			if terr := checkPasswordMeetsRequirements(config, *params.Password); terr != nil {
				return terr
			}

			if terr := user.UpdatePassword(tx, *params.Password); terr != nil {
				return terr
			}
		}

		if params.Email != "" {
			if terr := user.SetEmail(tx, params.Email); terr != nil {
				return terr
			}
		}

		if params.Phone != "" {
			if terr := user.SetPhone(tx, params.Phone); terr != nil {
				return terr
			}
		}

		if params.AppMetaData != nil {
			if terr := user.UpdateAppMetaData(tx, params.AppMetaData); terr != nil {
				return terr
			}
		}

		if params.UserMetaData != nil {
			if terr := user.UpdateUserMetaData(tx, params.UserMetaData); terr != nil {
				return terr
			}
		}

		if params.BanDuration != "" {
			if params.BanDuration == "none" {
				user.BannedUntil = nil
			} else {
				duration, terr := time.ParseDuration(params.BanDuration)
				if terr != nil {
					return badRequestError("Invalid format for ban_duration: %v", terr)
				}
				t := time.Now().Add(duration)
				user.BannedUntil = &t
			}
			if terr := user.UpdateBannedUntil(tx); terr != nil {
				return terr
			}
		}

		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.UserModifiedAction, "", map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return terr
		}
		return nil
	})

	if err != nil {
		if _, ok := err.(*HTTPError); ok {
			return err
		}
		if strings.Contains(err.Error(), "Invalid format for ban_duration") {
			return err
		}
		return internalServerError("Error updating user").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, user)
}

// adminUserCreate creates a new user based on the provided data
func (a *API) adminUserCreate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	adminUser := getAdminUser(ctx)
	params, err := a.getAdminParams(r)
	if err != nil {
		return err
	}

	aud := a.requestAud(ctx, r)
	if params.Aud != "" {
		aud = params.Aud
	}

	if params.Email == "" && params.Phone == "" {
		return unprocessableEntityError("Cannot create a user without either an email or phone")
	}

	if params.Email != "" {
		params.Email, err = a.validateEmail(ctx, params.Email)
		if err != nil {
			return err
		}
		if exists, err := models.IsDuplicatedEmail(db, params.Email, aud); err != nil {
			return internalServerError("Database error checking email").WithInternalError(err)
		} else if exists {
			return unprocessableEntityError("Email address already registered by another user")
		}
	}

	if params.Phone != "" {
		params.Phone, err = a.validatePhone(params.Phone)
		if err != nil {
			return err
		}
		if exists, err := models.IsDuplicatedPhone(db, params.Phone, aud); err != nil {
			return internalServerError("Database error checking phone").WithInternalError(err)
		} else if exists {
			return unprocessableEntityError("Phone number already registered by another user")
		}
	}

	if params.Password == nil || *params.Password == "" {
		password, err := password.Generate(64, 10, 0, false, true)
		if err != nil {
			return internalServerError("Error generating password").WithInternalError(err)
		}
		params.Password = &password
	}

	user, err := models.NewUser(params.Phone, params.Email, *params.Password, aud, params.UserMetaData)
	if err != nil {
		return internalServerError("Error creating user").WithInternalError(err)
	}

	if user.AppMetaData == nil {
		user.AppMetaData = make(map[string]interface{})
	}
	user.AppMetaData["provider"] = "email"
	user.AppMetaData["providers"] = []string{"email"}

	if params.BanDuration != "" {
		duration, terr := time.ParseDuration(params.BanDuration)
		if terr != nil {
			return badRequestError("Invalid format for ban_duration: %v", terr)
		}
		t := time.Now().Add(duration)
		user.BannedUntil = &t
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.UserSignedUpAction, "", map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return terr
		}

		if terr := tx.Create(user); terr != nil {
			return terr
		}

		role := config.JWT.DefaultGroupName
		if params.Role != "" {
			role = params.Role
		}
		if terr := user.SetRole(tx, role); terr != nil {
			return terr
		}

		if params.AppMetaData != nil {
			if terr := user.UpdateAppMetaData(tx, params.AppMetaData); terr != nil {
				return terr
			}
		}

		if params.EmailConfirm {
			if terr := user.Confirm(tx); terr != nil {
				return terr
			}
		}

		if params.PhoneConfirm {
			if terr := user.ConfirmPhone(tx); terr != nil {
				return terr
			}
		}

		return nil
	})

	if err != nil {
		if strings.Contains(err.Error(), "Invalid format for ban_duration") {
			return err
		}
		return internalServerError("Database error creating new user").WithInternalError(err)
	}

	return sendJSON(w, http.StatusOK, user)
}

// adminUserDelete delete a user
func (a *API) adminUserDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	user := getUser(ctx)
	adminUser := getAdminUser(ctx)

	err := db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.UserDeletedAction, "", map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return internalServerError("Error recording audit log entry").WithInternalError(terr)
		}

		if terr := tx.Destroy(user); terr != nil {
			return internalServerError("Database error deleting user").WithInternalError(terr)
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]interface{}{})
}

func (a *API) adminUserDeleteFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	factor := getFactor(ctx)

	MFAEnabled, err := models.IsMFAEnabled(a.db, user)
	if err != nil {
		return err
	} else if !MFAEnabled {
		return forbiddenError("You do not have a verified factor enrolled")
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, user, models.DeleteFactorAction, r.RemoteAddr, map[string]interface{}{
			"user_id":   user.ID,
			"factor_id": factor.ID,
		}); terr != nil {
			return terr
		}
		if terr := tx.Destroy(factor); terr != nil {
			return internalServerError("Database error deleting factor").WithInternalError(terr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, factor)
}

func (a *API) adminUserGetFactors(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	factors, terr := models.FindFactorsByUser(a.db, user)
	if terr != nil {
		return terr
	}
	return sendJSON(w, http.StatusOK, factors)
}

// adminUserUpdate updates a single factor object
func (a *API) adminUserUpdateFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	factor := getFactor(ctx)
	user := getUser(ctx)
	adminUser := getAdminUser(ctx)
	params := &adminUserUpdateFactorParams{}
	body, err := getBodyBytes(r)
	if err != nil {
		return badRequestError("Could not read body").WithInternalError(err)
	}

	if err := json.Unmarshal(body, params); err != nil {
		return badRequestError("Could not read factor update params: %v", err)
	}

	err = a.db.Transaction(func(tx *storage.Connection) error {
		if params.FriendlyName != "" {
			if terr := factor.UpdateFriendlyName(tx, params.FriendlyName); terr != nil {
				return terr
			}
		}
		if params.FactorType != "" {
			if params.FactorType != models.TOTP {
				return badRequestError("Factor Type not valid")
			}
			if terr := factor.UpdateFactorType(tx, params.FactorType); terr != nil {
				return terr
			}
		}

		if terr := models.NewAuditLogEntry(r, tx, adminUser, models.UpdateFactorAction, "", map[string]interface{}{
			"user_id":     user.ID,
			"factor_id":   factor.ID,
			"factor_type": factor.FactorType,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, factor)
}
