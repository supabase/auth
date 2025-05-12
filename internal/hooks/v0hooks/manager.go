package v0hooks

import (
	"context"
	"net/http"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/dispatch"
	"github.com/supabase/auth/internal/hooks/hookhttp"
	"github.com/supabase/auth/internal/hooks/hookpgfunc"
	"github.com/supabase/auth/internal/storage"
)

type Manager struct {
	config *conf.GlobalConfiguration
	v0http hookhttp.Service
	dr     dispatch.Service
}

func New(
	config *conf.GlobalConfiguration,
	httpSvc hookhttp.Service,
	pgfuncSvc hookpgfunc.Service,
) *Manager {
	return &Manager{
		config: config,
		v0http: httpSvc,
		dr:     dispatch.New(httpSvc, pgfuncSvc),
	}
}

func configByName(
	cfg *conf.HookConfiguration,
	name Name,
) (*conf.ExtensibilityPointConfiguration, bool) {
	switch name {
	case SendSMS:
		return &cfg.SendSMS, true
	case SendEmail:
		return &cfg.SendEmail, true
	case CustomizeAccessToken:
		return &cfg.CustomAccessToken, true
	case MFAVerification:
		return &cfg.MFAVerificationAttempt, true
	case PasswordVerification:
		return &cfg.PasswordVerificationAttempt, true
	case BeforeUserCreated:
		return &cfg.BeforeUserCreated, true
	case AfterUserCreated:
		return &cfg.AfterUserCreated, true
	default:
		return nil, false
	}
}

func (o *Manager) Enabled(name Name) bool {
	if cfg, ok := configByName(&o.config.Hook, name); ok {
		return cfg.Enabled
	}
	return false
}

func (o *Manager) BeforeUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *BeforeUserCreatedRequest,
	res *BeforeUserCreatedResponse,
) error {
	return o.dr.Dispatch(ctx, &o.config.Hook.BeforeUserCreated, tx, req, res)
}

func (o *Manager) AfterUserCreated(
	ctx context.Context,
	tx *storage.Connection,
	req *AfterUserCreatedRequest,
	res *AfterUserCreatedResponse,
) error {
	return o.dr.Dispatch(ctx, &o.config.Hook.AfterUserCreated, tx, req, res)
}

func (o *Manager) InvokeHook(
	conn *storage.Connection,
	r *http.Request,
	input, output any,
) error {
	return o.invokeHook(conn, r, input, output)
}

func (o *Manager) RunHTTPHook(
	r *http.Request,
	hookConfig conf.ExtensibilityPointConfiguration,
	input any,
) ([]byte, error) {
	return o.v0http.RunHTTPHook(r.Context(), hookConfig, input)
}

// invokeHook invokes the hook code. conn can be nil, in which case a new
// transaction is opened. If calling invokeHook within a transaction, always
// pass the current transaction, as pool-exhaustion deadlocks are very easy to
// trigger.
func (o *Manager) invokeHook(
	conn *storage.Connection,
	r *http.Request,
	input, output any,
) error {
	switch input.(type) {
	default:
		return apierrors.NewInternalServerError(
			"Unknown hook type %T.", input)

	case *SendSMSInput:
		if _, ok := output.(*SendSMSOutput); !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.SendSMSOutput")
		}
		return o.dr.Dispatch(
			r.Context(), &o.config.Hook.SendSMS, conn, input, output)

	case *SendEmailInput:
		if _, ok := output.(*SendEmailOutput); !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.SendEmailOutput")
		}
		return o.dr.Dispatch(
			r.Context(), &o.config.Hook.SendEmail, conn, input, output)

	case *MFAVerificationAttemptInput:
		if _, ok := output.(*MFAVerificationAttemptOutput); !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.MFAVerificationAttemptOutput")
		}
		return o.dr.Dispatch(
			r.Context(), &o.config.Hook.MFAVerificationAttempt, conn, input, output)

	case *PasswordVerificationAttemptInput:
		if _, ok := output.(*PasswordVerificationAttemptOutput); !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.PasswordVerificationAttemptOutput")
		}
		return o.dr.Dispatch(
			r.Context(), &o.config.Hook.PasswordVerificationAttempt, conn, input, output)

	case *CustomAccessTokenInput:
		_, ok := output.(*CustomAccessTokenOutput)
		if !ok {
			return apierrors.NewInternalServerError(
				"output should be *hooks.CustomAccessTokenOutput")
		}
		return o.dr.Dispatch(
			r.Context(), &o.config.Hook.CustomAccessToken, conn, input, output)
	}
}
