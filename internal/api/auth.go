package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
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

func (a *API) requireNotAnonymous(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	claims := getClaims(ctx)
	if claims.IsAnonymous {
		return nil, forbiddenError(ErrorCodeNoAuthorization, "Anonymous user not allowed to perform these actions")
	}
	return ctx, nil
}

func (a *API) requireAdmin(ctx context.Context, r *http.Request) (context.Context, error) {
	// Find the administrative user
	claims := getClaims(ctx)
	if claims == nil {
		fmt.Printf("[%s] %s %s %d %s\n", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.RequestURI, http.StatusForbidden, "Invalid token")
		return nil, forbiddenError(ErrorCodeBadJWT, "Invalid token")
	}

	adminRoles := a.config.JWT.AdminRoles

	if isStringInSlice(claims.Role, adminRoles) {
		// successful authentication
		return withAdminUser(ctx, &models.User{Role: claims.Role, Email: storage.NullString(claims.Role)}), nil
	}

	fmt.Printf("[%s] %s %s %d %s\n", time.Now().Format("2006-01-02 15:04:05"), r.Method, r.RequestURI, http.StatusForbidden, "this token needs role 'supabase_admin' or 'service_role'")
	return nil, forbiddenError(ErrorCodeNotAdmin, "User not allowed")
}

func (a *API) extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	matches := bearerRegexp.FindStringSubmatch(authHeader)
	if len(matches) != 2 {
		return "", httpError(http.StatusUnauthorized, ErrorCodeNoAuthorization, "This endpoint requires a Bearer token")
	}

	return matches[1], nil
}

func (a *API) parseJWTClaims(bearer string, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	config := a.config

	p := jwt.Parser{ValidMethods: []string{jwt.SigningMethodHS256.Name}}
	token, err := p.ParseWithClaims(bearer, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.JWT.Secret), nil
	})
	if err != nil {
		return nil, forbiddenError(ErrorCodeBadJWT, "invalid JWT: unable to parse or verify signature, %v", err).WithInternalError(err)
	}

	return withToken(ctx, token), nil
}

func (a *API) maybeLoadUserOrSession(ctx context.Context) (context.Context, error) {
	db := a.db.WithContext(ctx)
	claims := getClaims(ctx)

	if claims == nil {
		return ctx, forbiddenError(ErrorCodeBadJWT, "invalid token: missing claims")
	}

	if claims.Subject == "" {
		return nil, forbiddenError(ErrorCodeBadJWT, "invalid claim: missing sub claim")
	}

	var user *models.User
	if claims.Subject != "" {
		userId, err := uuid.FromString(claims.Subject)
		if err != nil {
			return ctx, badRequestError(ErrorCodeBadJWT, "invalid claim: sub claim must be a UUID").WithInternalError(err)
		}
		user, err = models.FindUserByID(db, userId)
		if err != nil {
			if models.IsNotFoundError(err) {
				return ctx, forbiddenError(ErrorCodeUserNotFound, "User from sub claim in JWT does not exist")
			}
			return ctx, err
		}
		ctx = withUser(ctx, user)
	}

	var session *models.Session
	if claims.SessionId != "" && claims.SessionId != uuid.Nil.String() {
		sessionId, err := uuid.FromString(claims.SessionId)
		if err != nil {
			return ctx, forbiddenError(ErrorCodeBadJWT, "invalid claim: session_id claim must be a UUID").WithInternalError(err)
		}
		session, err = models.FindSessionByID(db, sessionId, false)
		if err != nil && !models.IsNotFoundError(err) {
			return ctx, forbiddenError(ErrorCodeSessionNotFound, "Session from session_id claim in JWT does not exist")
		}
		ctx = withSession(ctx, session)
	}
	return ctx, nil
}
