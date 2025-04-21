package reloader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/supabase/auth/internal/conf"
	"golang.org/x/sync/errgroup"
)

func TestLoadConfigFile(t *testing.T) {
	// test bad multi line config value
	if err := godotenv.Overload("testdata/60_example_newline.env"); err != nil {
		t.Fatal(err)
	}
}

func TestWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	dir, cleanup := helpTestDir(t)
	defer cleanup()

	// test broken watcher
	{
		sentinelErr := errors.New("sentinel")
		rr := mockReloadRecorder()
		rl := NewReloader(dir)
		rl.watchFn = func() (watcher, error) { return nil, sentinelErr }

		err := rl.Watch(ctx, rr.configFn)
		if exp, got := sentinelErr, err; exp != got {
			assert.Equal(t, exp, got)
		}
	}

	// test watch invalid dir
	{
		doneCtx, doneCancel := context.WithCancel(ctx)
		doneCancel()

		rr := mockReloadRecorder()
		rl := NewReloader(path.Join(dir, "__not_found__"))
		err := rl.Watch(doneCtx, rr.configFn)
		if exp, got := context.Canceled, err; exp != got {
			assert.Equal(t, exp, got)
		}
	}

	// test watch invalid dir in addDirFn
	{

		sentinel := errors.New("sentinel")
		wr := newMockWatcher(sentinel)
		rl := NewReloader(path.Join(dir, "__not_found__"))
		rl.watchFn = func() (watcher, error) { return wr, nil }

		err := rl.addDirFn(ctx, wr, "__not_found__", time.Millisecond)
		if exp, got := sentinel, err; exp != got {
			assert.Equal(t, exp, got)
		}
	}

	// test watch error chan closed
	{
		rr := mockReloadRecorder()
		wr := newMockWatcher(nil)
		wr.errorCh <- errors.New("sentinel")
		close(wr.errorCh)

		rl := NewReloader(dir)
		rl.watchFn = func() (watcher, error) { return wr, nil }

		err := rl.Watch(ctx, rr.configFn)
		assert.NotNil(t, err)

		msg := "reloader: fsnotify error channel was closed"
		if exp, got := msg, err.Error(); exp != got {
			assert.Equal(t, exp, got)
		}
	}

	// test watch event chan closed
	{
		rr := mockReloadRecorder()
		wr := newMockWatcher(nil)
		close(wr.eventCh)

		rl := NewReloader(dir)
		rl.reloadIval = time.Second / 100
		rl.watchFn = func() (watcher, error) { return wr, nil }

		err := rl.Watch(ctx, rr.configFn)
		if err == nil {
			assert.NotNil(t, err)
		}

		msg := "reloader: fsnotify event channel was closed"
		if exp, got := msg, err.Error(); exp != got {
			assert.Equal(t, exp, got)
		}
	}

	// test watch error chan
	{
		rr := mockReloadRecorder()
		wr := newMockWatcher(nil)
		wr.errorCh <- errors.New("sentinel")

		rl := NewReloader(dir)
		rl.watchFn = func() (watcher, error) { return wr, nil }

		egCtx, egCancel := context.WithCancel(ctx)
		defer egCancel()

		var eg errgroup.Group
		eg.Go(func() error {
			return rl.Watch(egCtx, rr.configFn)
		})

		// need to ensure errorCh drains so test isn't racey
		eg.Go(func() error {
			defer egCancel()

			tr := time.NewTicker(time.Second / 100)
			defer tr.Stop()

			for {
				select {
				case <-egCtx.Done():
					return egCtx.Err()
				case <-tr.C:
					if len(wr.errorCh) == 0 {
						return nil
					}
				}
			}
		})

		err := eg.Wait()
		if exp, got := context.Canceled, err; exp != got {
			assert.Equal(t, exp, got)
		}
	}

	// test an end to end config reload
	{
		rr := mockReloadRecorder()
		wr := newMockWatcher(nil)
		rl := NewReloader(dir)
		rl.watchFn = func() (watcher, error) { return wr, wr.getErr() }
		rl.reloadFn = rr.reloadFn
		rl.addDirFn = func(ctx context.Context, wr watcher, dir string, dur time.Duration) error {
			if err := wr.Add(dir); err != nil {
				logrus.WithError(err).Error("reloader: error watching config directory")
				return err
			}
			return nil
		}

		// Need to lower reload ival to pickup config write quicker.
		rl.reloadIval = time.Second / 10
		rl.tickerIval = rl.reloadIval / 10

		egCtx, egCancel := context.WithCancel(ctx)
		defer egCancel()

		var eg errgroup.Group
		eg.Go(func() error {
			return rl.Watch(egCtx, rr.configFn)
		})

		// Copy a full and valid example configuration to trigger Watch
		{
			select {
			case <-egCtx.Done():
				assert.Nil(t, egCtx.Err())
			case v := <-wr.addCh:
				assert.Equal(t, v, dir)
			}

			name := helpCopyEnvFile(t, dir, "01_example.env", "testdata/50_example.env")
			wr.eventCh <- fsnotify.Event{
				Name: name,
				Op:   fsnotify.Create,
			}
			select {
			case <-egCtx.Done():
				assert.Nil(t, egCtx.Err())
			case cfg := <-rr.configCh:
				assert.NotNil(t, cfg)
				assert.Equal(t, cfg.External.Apple.Enabled, false)
			}
		}

		{
			drain(rr.configCh)
			drain(rr.reloadCh)

			name := helpWriteEnvFile(t, dir, "02_example.env", map[string]string{
				"GOTRUE_EXTERNAL_APPLE_ENABLED": "true",
			})
			wr.eventCh <- fsnotify.Event{
				Name: name,
				Op:   fsnotify.Create,
			}
			select {
			case <-egCtx.Done():
				assert.Nil(t, egCtx.Err())
			case cfg := <-rr.configCh:
				assert.NotNil(t, cfg)
				assert.Equal(t, cfg.External.Apple.Enabled, true)
			}
		}

		{
			name := helpWriteEnvFile(t, dir, "03_example.env.bak", map[string]string{
				"GOTRUE_EXTERNAL_APPLE_ENABLED": "false",
			})
			wr.eventCh <- fsnotify.Event{
				Name: name,
				Op:   fsnotify.Create,
			}
		}

		{
			// empty the reload ch
			drain(rr.reloadCh)

			name := helpWriteEnvFile(t, dir, "04_example.env", map[string]string{
				"GOTRUE_SMTP_PORT": "ABC",
			})
			wr.eventCh <- fsnotify.Event{
				Name: name,
				Op:   fsnotify.Create,
			}

			select {
			case <-egCtx.Done():
				assert.Nil(t, egCtx.Err())
			case p := <-rr.reloadCh:
				if exp, got := dir, p; exp != got {
					assert.Equal(t, exp, got)
				}
			}
		}

		{
			name := helpWriteEnvFile(t, dir, "05_example.env", map[string]string{
				"GOTRUE_SMTP_PORT": "2222",
			})
			wr.eventCh <- fsnotify.Event{
				Name: name,
				Op:   fsnotify.Create,
			}
			select {
			case <-egCtx.Done():
				assert.Nil(t, egCtx.Err())
			case cfg := <-rr.configCh:
				assert.NotNil(t, cfg)
				assert.Equal(t, cfg.SMTP.Port, 2222)
			}
		}

		// test the wr.Add doesn't exit if bad watch dir is given during tick
		{
			// set the error on watcher
			sentinelErr := errors.New("sentinel")
			wr.setErr(sentinelErr)

			name := helpWriteEnvFile(t, dir, "05_example.env", map[string]string{
				"GOTRUE_SMTP_PORT": "2222",
			})
			wr.eventCh <- fsnotify.Event{
				Name: name,
				Op:   fsnotify.Create,
			}

			select {
			case <-egCtx.Done():
				assert.Nil(t, egCtx.Err())
			case cfg := <-rr.configCh:
				assert.NotNil(t, cfg)
				assert.Equal(t, cfg.SMTP.Port, 2222)
			}
		}

		// test cases ran, end context to unblock Wait()
		egCancel()

		err := eg.Wait()
		if exp, got := context.Canceled, err; exp != got {
			assert.Equal(t, exp, got)
		}
	}
}

func TestReloadConfig(t *testing.T) {
	dir, cleanup := helpTestDir(t)
	defer cleanup()

	rl := NewReloader(dir)

	// Copy the full and valid example configuration.
	helpCopyEnvFile(t, dir, "01_example.env", "testdata/50_example.env")
	{
		cfg, err := rl.reload()
		assert.Nil(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, cfg.External.Apple.Enabled, false)
	}

	helpWriteEnvFile(t, dir, "02_example.env", map[string]string{
		"GOTRUE_EXTERNAL_APPLE_ENABLED": "true",
	})
	{
		cfg, err := rl.reload()
		assert.Nil(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, cfg.External.Apple.Enabled, true)
	}

	helpWriteEnvFile(t, dir, "03_example.env.bak", map[string]string{
		"GOTRUE_EXTERNAL_APPLE_ENABLED": "false",
	})
	{
		cfg, err := rl.reload()
		assert.Nil(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, cfg.External.Apple.Enabled, true)
	}

	// test cfg reload failure
	helpWriteEnvFile(t, dir, "04_example.env", map[string]string{
		"PORT":             "INVALIDPORT",
		"GOTRUE_SMTP_PORT": "ABC",
	})
	{
		cfg, err := rl.reload()
		assert.NotNil(t, err)
		assert.Nil(t, cfg)
	}

	// test directory loading failure
	{
		cleanup()

		cfg, err := rl.reload()
		assert.NotNil(t, err)
		assert.Nil(t, cfg)
	}
}

func TestReloadCheckAt(t *testing.T) {
	const s10 = time.Second * 10

	now := time.Now()
	tests := []struct {
		rl             *Reloader
		at, lastUpdate time.Time
		exp            bool
	}{
		// no lastUpdate is set (time.IsZero())
		{
			rl:  &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			exp: false,
		},
		{
			rl:  &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:  now,
			exp: false,
		},

		// last update within reload interval
		{
			rl:         &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:         now,
			lastUpdate: now.Add(-s10 + 1),
			exp:        false,
		},
		{
			rl:         &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:         now,
			lastUpdate: now,
			exp:        false,
		},
		{
			rl:         &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:         now,
			lastUpdate: now.Add(s10 - 1),
			exp:        false,
		},
		{
			rl:         &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:         now,
			lastUpdate: now.Add(s10),
			exp:        false,
		},
		{
			rl:         &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:         now,
			lastUpdate: now.Add(s10 + 1),
			exp:        false,
		},
		{
			rl:         &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:         now,
			lastUpdate: now.Add(s10 * 2),
			exp:        false,
		},

		// last update was outside our reload interval
		{
			rl:         &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:         now,
			lastUpdate: now.Add(-s10),
			exp:        true,
		},
		{
			rl:         &Reloader{reloadIval: s10, tickerIval: s10 / 10},
			at:         now,
			lastUpdate: now.Add(-s10 - 1),
			exp:        true,
		},
	}
	for _, tc := range tests {
		rl := tc.rl
		assert.NotNil(t, rl)
		assert.Equal(t, rl.reloadCheckAt(tc.at, tc.lastUpdate), tc.exp)
	}
}

func helpTestDir(t testing.TB) (dir string, cleanup func()) {
	name := fmt.Sprintf("%v_%v", t.Name(), time.Now().Nanosecond())
	dir = filepath.Join("testdata", name)
	err := os.MkdirAll(dir, 0750)
	if err != nil && !os.IsExist(err) {
		assert.Nil(t, err)
	}
	return dir, func() { os.RemoveAll(dir) }
}

func helpCopyEnvFile(t testing.TB, dir, name, src string) string {
	data, err := os.ReadFile(src) // #nosec G304
	if err != nil {
		assert.Nil(t, err)
	}

	dst := filepath.Join(dir, name)
	err = os.WriteFile(dst, data, 0600)
	if err != nil {
		assert.Nil(t, err)
	}
	return dst
}

func helpWriteEnvFile(t testing.TB, dir, name string, values map[string]string) string {
	var buf bytes.Buffer
	for k, v := range values {
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(`"`)
		buf.WriteString(v)
		buf.WriteString(`"`)
		buf.WriteString("\n")
	}

	dst := filepath.Join(dir, name)
	err := os.WriteFile(dst, buf.Bytes(), 0600)
	assert.Nil(t, err)
	return dst
}

func mockReloadRecorder() *reloadRecorder {
	rr := &reloadRecorder{
		configCh: make(chan *conf.GlobalConfiguration, 1024),
		reloadCh: make(chan string, 1024),
	}
	return rr
}

func drain[C ~chan T, T any](ch C) (out []T) {
	for {
		select {
		case v := <-ch:
			out = append(out, v)
		default:
			return out
		}
	}
}

type reloadRecorder struct {
	configCh chan *conf.GlobalConfiguration
	reloadCh chan string
}

func (o *reloadRecorder) reloadFn(dir string) (*conf.GlobalConfiguration, error) {
	defer func() {
		select {
		case o.reloadCh <- dir:
		default:
		}
	}()
	return defaultReloadFn(dir)
}

func (o *reloadRecorder) configFn(gc *conf.GlobalConfiguration) {
	select {
	case o.configCh <- gc:
	default:
	}
}
