// Package dispatch is responsible for dispatching hook requests to the http
// or pgfunc packages. It is utilized by both the v0 and v1 hooks packages.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/v0hooks/v0http"
	"github.com/supabase/auth/internal/hooks/v0hooks/v0pgfunc"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

type Service interface {
	Dispatch(
		ctx context.Context,
		hookConfig *conf.ExtensibilityPointConfiguration,
		conn *storage.Connection,
		input, output any,
	) error
}

type Dispatcher struct {
	v0http   v0http.Service
	v0pgfunc v0pgfunc.Service
}

func New(
	v0http v0http.Service,
	v0pgfunc v0pgfunc.Service,
) *Dispatcher {
	o := &Dispatcher{
		v0http:   v0http,
		v0pgfunc: v0pgfunc,
	}
	return o
}

func (o *Dispatcher) Dispatch(
	ctx context.Context,
	hookConfig *conf.ExtensibilityPointConfiguration,
	conn *storage.Connection,
	input, output any,
) error {
	logEntry := observability.GetLogEntryFromContext(ctx)
	hookStart := time.Now()

	var err error
	switch {
	case strings.HasPrefix(hookConfig.URI, "http:") ||
		strings.HasPrefix(hookConfig.URI, "https:"):
		err = o.v0http.HTTPDispatch(ctx, *hookConfig, input, output)

	case strings.HasPrefix(hookConfig.URI, "pg-functions:"):
		err = o.v0pgfunc.PGFuncDispatch(ctx, *hookConfig, conn, input, output)

	default:
		return fmt.Errorf(
			"unsupported protocol: %q only postgres hooks and HTTPS functions"+
				" are supported at the moment", hookConfig.URI)
	}

	duration := time.Since(hookStart)

	if err != nil {
		logEntry.Entry.WithFields(logrus.Fields{
			"action":   "run_hook",
			"hook":     hookConfig.URI,
			"success":  false,
			"duration": duration.Microseconds(),
		}).WithError(err).Warn("Hook errored out")

		e := new(apierrors.HTTPError)
		if errors.As(err, &e) {
			return e
		}
		return apierrors.NewInternalServerError(
			"Error running hook URI: %v", hookConfig.URI).WithInternalError(err)
	}

	logEntry.Entry.WithFields(logrus.Fields{
		"action":   "run_hook",
		"hook":     hookConfig.URI,
		"success":  true,
		"duration": duration.Microseconds(),
	}).WithError(err).Info("Hook ran successfully")

	return nil
}
