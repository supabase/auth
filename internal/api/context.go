package api

import (
	"context"
	"net/url"

	jwt "github.com/golang-jwt/jwt"
	"github.com/supabase/auth/internal/models"
)

type contextKey string

func (c contextKey) String() string {
	return "gotrue api context key " + string(c)
}

const (
	tokenKey                = contextKey("jwt")
	requestIDKey            = contextKey("request_id")
	inviteTokenKey          = contextKey("invite_token")
	signatureKey            = contextKey("signature")
	externalProviderTypeKey = contextKey("external_provider_type")
	userKey                 = contextKey("user")
	targetUserKey           = contextKey("target_user")
	factorKey               = contextKey("factor")
	sessionKey              = contextKey("session")
	externalReferrerKey     = contextKey("external_referrer")
	functionHooksKey        = contextKey("function_hooks")
	adminUserKey            = contextKey("admin_user")
	oauthTokenKey           = contextKey("oauth_token") // for OAuth1.0, also known as request token
	oauthVerifierKey        = contextKey("oauth_verifier")
	ssoProviderKey          = contextKey("sso_provider")
	externalHostKey         = contextKey("external_host")
	flowStateKey            = contextKey("flow_state_id")
)

// withToken adds the JWT token to the context.
func withToken(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, tokenKey, token)
}

// getToken reads the JWT token from the context.
func getToken(ctx context.Context) *jwt.Token {
	obj := ctx.Value(tokenKey)
	if obj == nil {
		return nil
	}

	return obj.(*jwt.Token)
}

func getClaims(ctx context.Context) *AccessTokenClaims {
	token := getToken(ctx)
	if token == nil {
		return nil
	}
	return token.Claims.(*AccessTokenClaims)
}

// withRequestID adds the provided request ID to the context.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// getRequestID reads the request ID from the context.
func getRequestID(ctx context.Context) string {
	obj := ctx.Value(requestIDKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

// withUser adds the user to the context.
func withUser(ctx context.Context, u *models.User) context.Context {
	return context.WithValue(ctx, userKey, u)
}

// withTargetUser adds the target user for linking to the context.
func withTargetUser(ctx context.Context, u *models.User) context.Context {
	return context.WithValue(ctx, targetUserKey, u)
}

// with Factor adds the factor id to the context.
func withFactor(ctx context.Context, f *models.Factor) context.Context {
	return context.WithValue(ctx, factorKey, f)
}

// getUser reads the user from the context.
func getUser(ctx context.Context) *models.User {
	if ctx == nil {
		return nil
	}
	obj := ctx.Value(userKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.User)
}

// getTargetUser reads the user from the context.
func getTargetUser(ctx context.Context) *models.User {
	if ctx == nil {
		return nil
	}
	obj := ctx.Value(targetUserKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.User)
}

// getFactor reads the factor id from the context
func getFactor(ctx context.Context) *models.Factor {
	obj := ctx.Value(factorKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.Factor)
}

// withSession adds the session to the context.
func withSession(ctx context.Context, s *models.Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

// getSession reads the session from the context.
func getSession(ctx context.Context) *models.Session {
	if ctx == nil {
		return nil
	}
	obj := ctx.Value(sessionKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.Session)
}

// withSignature adds the provided request ID to the context.
func withSignature(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, signatureKey, id)
}

func withInviteToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, inviteTokenKey, token)
}

func withFlowStateID(ctx context.Context, FlowStateID string) context.Context {
	return context.WithValue(ctx, flowStateKey, FlowStateID)
}

func getFlowStateID(ctx context.Context) string {
	obj := ctx.Value(flowStateKey)
	if obj == nil {
		return ""
	}
	return obj.(string)
}

func getInviteToken(ctx context.Context) string {
	obj := ctx.Value(inviteTokenKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

// withExternalProviderType adds the provided request ID to the context.
func withExternalProviderType(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, externalProviderTypeKey, id)
}

// getExternalProviderType reads the request ID from the context.
func getExternalProviderType(ctx context.Context) string {
	obj := ctx.Value(externalProviderTypeKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

func withExternalReferrer(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, externalReferrerKey, token)
}

func getExternalReferrer(ctx context.Context) string {
	obj := ctx.Value(externalReferrerKey)
	if obj == nil {
		return ""
	}

	return obj.(string)
}

// getFunctionHooks reads the request ID from the context.
func getFunctionHooks(ctx context.Context) map[string][]string {
	obj := ctx.Value(functionHooksKey)
	if obj == nil {
		return map[string][]string{}
	}

	return obj.(map[string][]string)
}

// withAdminUser adds the admin user to the context.
func withAdminUser(ctx context.Context, u *models.User) context.Context {
	return context.WithValue(ctx, adminUserKey, u)
}

// getAdminUser reads the admin user from the context.
func getAdminUser(ctx context.Context) *models.User {
	obj := ctx.Value(adminUserKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.User)
}

// withRequestToken adds the request token to the context
func withRequestToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, oauthTokenKey, token)
}

func getRequestToken(ctx context.Context) string {
	obj := ctx.Value(oauthTokenKey)
	if obj == nil {
		return ""
	}
	return obj.(string)
}

func withOAuthVerifier(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, oauthVerifierKey, token)
}

func getOAuthVerifier(ctx context.Context) string {
	obj := ctx.Value(oauthVerifierKey)
	if obj == nil {
		return ""
	}
	return obj.(string)
}

func withSSOProvider(ctx context.Context, provider *models.SSOProvider) context.Context {
	return context.WithValue(ctx, ssoProviderKey, provider)
}

func getSSOProvider(ctx context.Context) *models.SSOProvider {
	obj := ctx.Value(ssoProviderKey)
	if obj == nil {
		return nil
	}
	return obj.(*models.SSOProvider)
}

func withExternalHost(ctx context.Context, u *url.URL) context.Context {
	return context.WithValue(ctx, externalHostKey, u)
}

func getExternalHost(ctx context.Context) *url.URL {
	obj := ctx.Value(externalHostKey)
	if obj == nil {
		return nil
	}
	return obj.(*url.URL)
}
