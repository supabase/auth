package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
)

// requireAuthentication checks incoming requests for tokens presented using the Authorization header
func (a *API) requireAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	token, err := a.extractBearerToken(w, r)
	config := a.config
	if err != nil {
		a.clearCookieTokens(config, w)
		return nil, err
	}

	ctx, err := a.parseJWTClaims(token, r, w)
	if err != nil {
		return ctx, err
	}

	ctx, err = a.maybeLoadUserOrSession(ctx)
	if err != nil {
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

func (a *API) extractBearerToken(w http.ResponseWriter, r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	matches := bearerRegexp.FindStringSubmatch(authHeader)
	if len(matches) != 2 {
		return "", unauthorizedError("This endpoint requires a Bearer token")
	}

	return matches[1], nil
}

func (a *API) parseJWTClaims(bearer string, r *http.Request, w http.ResponseWriter) (context.Context, error) {
	ctx := r.Context()
	config := a.config

	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	token, err := p.ParseWithClaims(bearer, &GoTrueClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWT.Secret), nil
	})
	if err != nil {
		a.clearCookieTokens(config, w)
		return nil, unauthorizedError("Invalid token: %v", err)
	}

	return withToken(ctx, token), nil
}

func (a *API) maybeLoadUserOrSession(ctx context.Context) (context.Context, error) {
	claims := getClaims(ctx)
	if claims == nil {
		return ctx, errors.New("invalid token")
	}

	if claims.Subject == "" {
		return nil, errors.New("invalid claim: subject missing")
	}

	var user *models.User
	if claims.Subject != "" {
		userId, err := uuid.FromString(claims.Subject)
		if err != nil {
			return ctx, err
		}
		user, err = models.FindUserByID(a.db, userId)
		if err != nil {
			return ctx, err
		}
		ctx = withUser(ctx, user)
	}

	var session *models.Session
	if claims.SessionId != "" {
		sessionId, err := uuid.FromString(claims.SessionId)
		if err != nil {
			return ctx, err
		}
		session, err = models.FindSessionById(a.db, sessionId)
		if err != nil {
			return ctx, err
		}
		ctx = withSession(ctx, session)
	}
	return ctx, nil
}
