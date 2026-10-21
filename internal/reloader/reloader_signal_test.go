//go:build !windows

package reloader

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/e2e"
	"golang.org/x/sync/errgroup"
)

func TestWatchSignals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	dir, cleanup := helpTestDir(t)
	defer cleanup()

	// test ctx cancel
	{
		doneCtx, doneCancel := context.WithCancel(ctx)
		doneCancel()

		cfg := e2e.Must(e2e.Config()).Reloading
		rl := NewReloader(cfg, dir)

		err := rl.watchSignal(doneCtx, nil)
		if exp, got := context.Canceled, err; exp != got {
			require.Equal(t, exp, got)
		}
	}

	{
		proc, err := os.FindProcess(os.Getpid())
		require.NoError(t, err)

		const sig = syscall.SIGUSR1
		cfg := e2e.Must(e2e.Config()).Reloading
		cfg.GracePeriodInterval = time.Second / 100
		cfg.PollerInterval = time.Second / 100
		cfg.SignalEnabled = true
		cfg.SignalNumber = int(sig)
		cfg.NotifyEnabled = true
		cfg.PollerEnabled = true

		rl := NewReloader(cfg, dir)

		egCtx, egCancel := context.WithCancel(ctx)
		defer egCancel()

		rr := mockReloadRecorder()
		gateCh := make(chan struct{})

		var eg errgroup.Group
		eg.Go(func() error {
			close(gateCh)

			return rl.Watch(egCtx, rr.configFn)
		})

		eg.Go(func() error {
			select {
			case <-gateCh:
			case <-egCtx.Done():
				return egCtx.Err()
			}

			tr := time.NewTicker(time.Second / 16)
			defer tr.Stop()

			after := time.After(time.Second / 4)
			for {
				select {
				case <-after:
					return nil
				case <-tr.C:
					if err := proc.Signal(sig); err != nil {
						return err
					}
				}
			}
		})

		// need to ensure errorCh drains so test isn't racey
		eg.Go(func() error {
			defer egCancel()

			select {
			case <-egCtx.Done():
				return egCtx.Err()
			case <-rr.configCh:
				egCancel()
				return nil
			}
		})

		err = eg.Wait()
		if exp, got := context.Canceled, err; exp != got {
			require.Equal(t, exp, got)
		}
	}
}
