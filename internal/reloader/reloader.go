// Package reloader provides support for live configuration reloading.
package reloader

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
)

const (
	// reloadInterval is the interval between configuration reloading. At most
	// one configuration change may be made between this duration.
	reloadInterval = time.Second * 10

	// tickerInterval is the maximum latency between configuration reloads.
	tickerInterval = reloadInterval / 10
)

type ConfigFunc func(*conf.GlobalConfiguration)

type Reloader struct {
	watchDir   string
	reloadIval time.Duration
	tickerIval time.Duration
	watchFn    func() (watcher, error)
	reloadFn   func(dir string) (*conf.GlobalConfiguration, error)
	addDirFn   func(ctx context.Context, wr watcher, dir string, dur time.Duration) error
}

func NewReloader(watchDir string) *Reloader {
	return &Reloader{
		watchDir:   watchDir,
		reloadIval: reloadInterval,
		tickerIval: tickerInterval,
		watchFn:    newFSWatcher,
		reloadFn:   defaultReloadFn,
		addDirFn:   defaultAddDirFn,
	}
}

// reload attempts to create a new *conf.GlobalConfiguration after loading the
// currently configured watchDir.
func (rl *Reloader) reload() (*conf.GlobalConfiguration, error) {
	return rl.reloadFn(rl.watchDir)
}

// reloadCheckAt checks if reloadConfig should be called, returns true if config
// should be reloaded or false otherwise.
func (rl *Reloader) reloadCheckAt(at, lastUpdate time.Time) bool {
	if lastUpdate.IsZero() {
		return false // no pending updates
	}
	if at.Sub(lastUpdate) < rl.reloadIval {
		return false // waiting for reload interval
	}

	// Update is pending.
	return true
}

func (rl *Reloader) Watch(ctx context.Context, fn ConfigFunc) error {
	wr, err := rl.watchFn()
	if err != nil {
		logrus.WithError(err).Error("reloader: error creating fsnotify Watcher")
		return err
	}
	defer wr.Close()

	tr := time.NewTicker(rl.tickerIval)
	defer tr.Stop()

	// Ignore errors, if watch dir doesn't exist we can add it later.
	if err := rl.addDirFn(ctx, wr, rl.watchDir, reloadInterval); err != nil {
		logrus.WithError(err).Error("reloader: error watching config directory")
	}

	var lastUpdate time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-tr.C:
			// This is a simple way to solve watch dir being added later or
			// being moved and then recreated. I've tested all of these basic
			// scenarios and wr.WatchList() does not grow which aligns with
			// the documented behavior.
			if err := rl.addDirFn(ctx, wr, rl.watchDir, reloadInterval); err != nil {
				logrus.WithError(err).Error("reloader: error watching config directory")
			}

			// Check to see if the config is ready to be relaoded.
			if !rl.reloadCheckAt(time.Now(), lastUpdate) {
				continue
			}

			// Reset the last update time before we try to reload the config.
			lastUpdate = time.Time{}

			cfg, err := rl.reload()
			if err != nil {
				logrus.WithError(err).Error("reloader: error loading config")
				continue
			}

			// Call the callback function with the latest cfg.
			fn(cfg)

		case evt, ok := <-wr.Events():
			if !ok {
				err := errors.New("reloader: fsnotify event channel was closed")
				logrus.WithError(err).Error(err)
				return err
			}

			// We only read files ending in .env
			if !strings.HasSuffix(evt.Name, ".env") {
				continue
			}

			switch {
			case evt.Op.Has(fsnotify.Create),
				evt.Op.Has(fsnotify.Remove),
				evt.Op.Has(fsnotify.Rename),
				evt.Op.Has(fsnotify.Write):
				lastUpdate = time.Now()
			}
		case err, ok := <-wr.Errors():
			if !ok {
				err := errors.New("reloader: fsnotify error channel was closed")
				logrus.WithError(err).Error(err)
				return err
			}
			logrus.WithError(err).Error(
				"reloader: fsnotify has reported an error")
		}
	}
}

// defaultAddDirFn adds a dir to a watcher with a common error and sleep
// duration if the directory doesn't exist.
func defaultAddDirFn(ctx context.Context, wr watcher, dir string, dur time.Duration) error {
	if err := wr.Add(dir); err != nil {
		tr := time.NewTicker(dur)
		defer tr.Stop()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tr.C:
			return err
		}
	}
	return nil
}

func defaultReloadFn(dir string) (*conf.GlobalConfiguration, error) {
	if err := conf.LoadDirectory(dir); err != nil {
		return nil, err
	}

	cfg, err := conf.LoadGlobalFromEnv()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

type watcher interface {
	Add(path string) error
	Close() error
	Events() chan fsnotify.Event
	Errors() chan error
}

type fsNotifyWatcher struct {
	wr *fsnotify.Watcher
}

func newFSWatcher() (watcher, error) {
	wr, err := fsnotify.NewWatcher()
	return &fsNotifyWatcher{wr}, err
}

func (o *fsNotifyWatcher) Add(path string) error       { return o.wr.Add(path) }
func (o *fsNotifyWatcher) Close() error                { return o.wr.Close() }
func (o *fsNotifyWatcher) Errors() chan error          { return o.wr.Errors }
func (o *fsNotifyWatcher) Events() chan fsnotify.Event { return o.wr.Events }

type mockWatcher struct {
	mu      sync.Mutex
	err     error
	eventCh chan fsnotify.Event
	errorCh chan error
	addCh   chan string
}

func newMockWatcher(err error) *mockWatcher {
	wr := &mockWatcher{
		err:     err,
		eventCh: make(chan fsnotify.Event, 1024),
		errorCh: make(chan error, 1024),
		addCh:   make(chan string, 1024),
	}
	return wr
}

func (o *mockWatcher) getErr() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	err := o.err
	return err
}

func (o *mockWatcher) setErr(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.err = err
}

func (o *mockWatcher) Add(path string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.err; err != nil {
		return err
	}

	select {
	case o.addCh <- path:
	default:
	}
	return nil
}
func (o *mockWatcher) Close() error                { return o.getErr() }
func (o *mockWatcher) Events() chan fsnotify.Event { return o.eventCh }
func (o *mockWatcher) Errors() chan error          { return o.errorCh }
