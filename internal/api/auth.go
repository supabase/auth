package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt"
	"github.com/supabase/gotrue/internal/models"
	"github.com/supabase/gotrue/internal/storage"
)

// requireAuthentication checks incoming requests for tokens presented using the Authorization header
func (a *API) requireAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	token, err := a.extractBearerToken(r)
	config := a.config
	if err != nil {
		a.clearCookieTokens(config, w)
		return nil, err
	}

	ctx, err := a.parseJWTClaims(token, r)
	if err != nil {
		a.clearCookieTokens(config, w)
		return ctx, err
	}

	ctx, err = a.maybeLoadUserOrSession(ctx)
	if err != nil {
		a.clearCookieTokens(config, w)
		return ctx, err
	}
	return ctx, err
}

func (a *API) requireAdmin(ctx context.Context, w http.ResponseWriter, r *http.Request) (context.Context, error) {
	// Find the administrative user
	claims := getClaims(ctx)
	if claims == nil {
		fmt.Printf("[%s] %s %s %d %s\n", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.RequestURI, http.StatusForbidden, "Invalid token")
		return nil, unauthorizedError("Invalid token")
	}

	adminRoles := a.config.JWT.AdminRoles

	if isStringInSlice(claims.Role, adminRoles) {
		// successful authentication
		return withAdminUser(ctx, &models.User{Role: claims.Role, Email: storage.NullString(claims.Role)}), nil
	}

	fmt.Printf("[%s] %s %s %d %s\n", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.RequestURI, http.StatusForbidden, "this token needs role 'supabase_admin' or 'service_role'")
	return nil, unauthorizedError("User not allowed")
}

func (a *API) extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	matches := bearerRegexp.FindStringSubmatch(authHeader)
	if len(matches) != 2 {
		return "", unauthorizedError("This endpoint requires a Bearer token")
	}

	return matches[1], nil
}

func (a *API) parseJWTClaims(bearer string, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	config := a.config

	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	token, err := p.ParseWithClaims(bearer, &GoTrueClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWT.Secret), nil
	})
	if err != nil {
		return nil, unauthorizedError("invalid JWT: unable to parse or verify signature, %v", err)
	}

	return withToken(ctx, token), nil
}

func (a *API) maybeLoadUserOrSession(ctx context.Context) (context.Context, error) {
	db := a.db.WithContext(ctx)
	claims := getClaims(ctx)

	if claims == nil {
		return ctx, unauthorizedError("invalid token: missing claims")
	}

	if claims.Subject == "" {
		return nil, unauthorizedError("invalid claim: missing sub claim")
	}

	var user *models.User
	if claims.Subject != "" {
		userId, err := uuid.FromString(claims.Subject)
		if err != nil {
			return ctx, badRequestError("invalid claim: sub claim must be a UUID").WithInternalError(err)
		}
		user, err = models.FindUserByID(db, userId)
		if err != nil {
			if models.IsNotFoundError(err) {
				return ctx, notFoundError(err.Error())
			}
			return ctx, err
		}
		ctx = withUser(ctx, user)
	}

	var session *models.Session
	if claims.SessionId != "" && claims.SessionId != uuid.Nil.String() {
		sessionId, err := uuid.FromString(claims.SessionId)
		if err != nil {
			return ctx, err
		}
		session, err = models.FindSessionByID(db, sessionId)
		if err != nil && !models.IsNotFoundError(err) {
			return ctx, err
		}
		ctx = withSession(ctx, session)
	}
	return ctx, nil
}
