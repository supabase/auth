package api

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// requireAuthentication checks incoming requests for tokens presented using the Authorization header
func (a *API) requireAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	token, err := a.extractBearerToken(r)
	if err != nil {
		return nil, err
	}

	ctx, err := a.parseJWTClaims(token, r)
	if err != nil {
		return ctx, err
	}

	ctx, err = a.maybeLoadUserOrSession(ctx)
	if err != nil {
		return ctx, err
	}
	return ctx, err
}

// loadAuthentication is similar to requireAuthentication, but it only loads
// the user authentication if there is an Authorization header and (for
// backward compatibility) if there is a query param grant_type == id_token. If
// there is none, it does nothing. If there is one but has invalid claims, it
// rejects.
func (a *API) loadAuthentication(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	if !strings.HasSuffix(r.URL.Path, "/token") || r.URL.Query().Get("grant_type") == "id_token" {
		// We don't know if client libraries _never_ send a JWT on any
		// `/token` endpoint. They likely don't but to keep backward
		// compatibility this only applies for the id_token grant.

		if value := r.Header.Get("Authorization"); value != "" {
			return a.requireAuthentication(w, r)
		}
	}

	return r.Context(), nil
}

func (a *API) requireNotAnonymous(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	claims := getClaims(ctx)
	if claims.IsAnonymous {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeNoAuthorization, "Anonymous user not allowed to perform these actions")
	}
	return ctx, nil
}

func (a *API) requireAdmin(ctx context.Context) (context.Context, error) {
	// Find the administrative user
	claims := getClaims(ctx)
	if claims == nil {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeBadJWT, "Invalid token")
	}

	adminRoles := a.config.JWT.AdminRoles

	if slices.Contains(adminRoles, claims.Role) {
		// successful authentication
		return withAdminUser(ctx, &models.User{Role: claims.Role, Email: storage.NullString(claims.Role)}), nil
	}

	return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeNotAdmin, "User not allowed").WithInternalMessage(fmt.Sprintf("this token needs to have one of the following roles: %v", strings.Join(adminRoles, ", ")))
}

func (a *API) extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	matches := bearerRegexp.FindStringSubmatch(authHeader)
	if len(matches) != 2 {
		return "", apierrors.NewHTTPError(http.StatusUnauthorized, apierrors.ErrorCodeNoAuthorization, "This endpoint requires a valid Bearer token")
	}

	return matches[1], nil
}

func (a *API) parseJWTClaims(bearer string, r *http.Request) (context.Context, error) {
	ctx := r.Context()
	config := a.config

	p := jwt.NewParser(jwt.WithValidMethods(config.JWT.ValidMethods))
	token, err := p.ParseWithClaims(bearer, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if kid, ok := token.Header["kid"]; ok {
			if kidStr, ok := kid.(string); ok {
				key, err := conf.FindPublicKeyByKid(kidStr, &config.JWT)
				if err != nil {
					return nil, err
				}
				if key != nil {
					return key, nil
				}

				// otherwise try to use fallback
			}
		}
		if alg, ok := token.Header["alg"]; ok {
			if alg == jwt.SigningMethodHS256.Name {
				// preserve backward compatibility for cases where the kid is not set
				return []byte(config.JWT.Secret), nil
			}
		}

		return nil, fmt.Errorf("unrecognized JWT kid %v for algorithm %v", token.Header["kid"], token.Header["alg"])
	})
	if err != nil {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeBadJWT, "invalid JWT: unable to parse or verify signature, %v", err).WithInternalError(err)
	}

	return withToken(ctx, token), nil
}

func (a *API) maybeLoadUserOrSession(ctx context.Context) (context.Context, error) {
	db := a.db.WithContext(ctx)
	claims := getClaims(ctx)

	if claims == nil {
		return ctx, apierrors.NewForbiddenError(apierrors.ErrorCodeBadJWT, "invalid token: missing claims")
	}

	if claims.Subject == "" {
		return nil, apierrors.NewForbiddenError(apierrors.ErrorCodeBadJWT, "invalid claim: missing sub claim")
	}

	var user *models.User
	if claims.Subject != "" {
		userId, err := uuid.FromString(claims.Subject)
		if err != nil {
			return ctx, apierrors.NewBadRequestError(apierrors.ErrorCodeBadJWT, "invalid claim: sub claim must be a UUID").WithInternalError(err)
		}
		user, err = models.FindUserByID(db, userId)
		if err != nil {
			if models.IsNotFoundError(err) {
				return ctx, apierrors.NewForbiddenError(apierrors.ErrorCodeUserNotFound, "User from sub claim in JWT does not exist")
			}
			return ctx, err
		}
		ctx = withUser(ctx, user)
	}

	var session *models.Session
	if claims.SessionId != "" && claims.SessionId != uuid.Nil.String() {
		sessionId, err := uuid.FromString(claims.SessionId)
		if err != nil {
			return ctx, apierrors.NewForbiddenError(apierrors.ErrorCodeBadJWT, "invalid claim: session_id claim must be a UUID").WithInternalError(err)
		}
		session, err = models.FindSessionByID(db, sessionId, false)
		if err != nil {
			if models.IsNotFoundError(err) {
				return ctx, apierrors.NewForbiddenError(apierrors.ErrorCodeSessionNotFound, "Session from session_id claim in JWT does not exist").WithInternalError(err).WithInternalMessage(fmt.Sprintf("session id (%s) doesn't exist", sessionId))
			}
			return ctx, err
		}
		ctx = withSession(ctx, session)
	}
	return ctx, nil
}
