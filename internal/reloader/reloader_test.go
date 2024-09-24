package reloader

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReloadConfig(t *testing.T) {
	dir, cleanup := helpTestDir(t)
	defer cleanup()

	rl := NewReloader(dir)

	// Copy the full and valid example configuration.
	helpCopyEnvFile(t, dir, "01_example.env", "testdata/50_example.env")
	{
		cfg, err := rl.reload()
		if err != nil {
			t.Fatal(err)
		}
		assert.NotNil(t, cfg)
		assert.Equal(t, cfg.External.Apple.Enabled, false)
	}

	helpWriteEnvFile(t, dir, "02_example.env", map[string]string{
		"GOTRUE_EXTERNAL_APPLE_ENABLED": "true",
	})
	{
		cfg, err := rl.reload()
		if err != nil {
			t.Fatal(err)
		}
		assert.NotNil(t, cfg)
		assert.Equal(t, cfg.External.Apple.Enabled, true)
	}

	helpWriteEnvFile(t, dir, "03_example.env.bak", map[string]string{
		"GOTRUE_EXTERNAL_APPLE_ENABLED": "false",
	})
	{
		cfg, err := rl.reload()
		if err != nil {
			t.Fatal(err)
		}
		assert.NotNil(t, cfg)
		assert.Equal(t, cfg.External.Apple.Enabled, true)
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
	dir = filepath.Join("testdata", t.Name())
	err := os.MkdirAll(dir, 0750)
	if err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	return dir, func() { os.RemoveAll(dir) }
}

func helpCopyEnvFile(t testing.TB, dir, name, src string) string {
	data, err := os.ReadFile(src) // #nosec G304
	if err != nil {
		log.Fatal(err)
	}

	dst := filepath.Join(dir, name)
	err = os.WriteFile(dst, data, 0600)
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func helpWriteEnvFile(t testing.TB, dir, name string, values map[string]string) string {
	var buf bytes.Buffer
	for k, v := range values {
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(v)
		buf.WriteString("\n")
	}

	dst := filepath.Join(dir, name)
	err := os.WriteFile(dst, buf.Bytes(), 0600)
	if err != nil {
		t.Fatal(err)
	}
	return dst
}
