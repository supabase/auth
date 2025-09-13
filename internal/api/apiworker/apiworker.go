package apiworker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/mailer/templatemailer"
)

// Worker is a simple background worker for async tasks.
type Worker struct {
	le *logrus.Entry
	tc *templatemailer.Cache

	// Notifies worker the cfg has been updated.
	cfgCh chan struct{}

	// workMu must be held for calls to Work
	workMu sync.Mutex

	// mu must be held for field access below here
	mu  sync.Mutex
	cfg *conf.GlobalConfiguration
}

// New will return a new *Worker instance.
func New(
	cfg *conf.GlobalConfiguration,
	tc *templatemailer.Cache,
	le *logrus.Entry,
) *Worker {
	return &Worker{
		le:    le,
		cfg:   cfg,
		tc:    tc,
		cfgCh: make(chan struct{}, 1),
	}
}

func (o *Worker) putConfig(cfg *conf.GlobalConfiguration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cfg = cfg
}

func (o *Worker) getConfig() *conf.GlobalConfiguration {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cfg
}

// ReloadConfig notifies the worker a new configuration is available.
func (o *Worker) ReloadConfig(cfg *conf.GlobalConfiguration) {
	o.putConfig(cfg)

	select {
	case o.cfgCh <- struct{}{}:
	default:
	}
}

// Work will periodically reload the templates in the background as long as the
// system remains active.
func (o *Worker) Work(ctx context.Context) error {
	if ok := o.workMu.TryLock(); !ok {
		return errors.New("apiworker: concurrent calls to Work are invalid")
	}
	defer o.workMu.Unlock()

	le := o.le.WithFields(logrus.Fields{
		"worker_type": "apiworker_template_cache",
	})
	le.Info("apiworker: template cache worker started")
	defer le.Info("apiworker: template cache worker exited")

	// Reload templates right away on Work.
	o.maybeReloadTemplates(ctx, o.getConfig())

	ival := func() time.Duration {
		return max(time.Second, o.getConfig().Mailer.TemplateRetryInterval/4)
	}

	tr := time.NewTicker(ival())
	defer tr.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-o.cfgCh:
			tr.Reset(ival())
		case <-tr.C:
		}

		// Either ticker fired or we got a config update.
		o.maybeReloadTemplates(ctx, o.getConfig())
	}
}

func (o *Worker) maybeReloadTemplates(
	ctx context.Context,
	cfg *conf.GlobalConfiguration,
) {
	if cfg.Mailer.TemplateReloadingEnabled {
		o.tc.Reload(ctx, cfg)
	}
}
