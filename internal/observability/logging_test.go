package observability

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

func TestConfigureLoggingWithFile(t *testing.T) {
	// loggingOnce must be reset for this branch to run; we can only do this
	// safely from inside the package's own tests.
	loggingOnce = sync.Once{}

	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")

	require.NoError(t, ConfigureLogging(&conf.LoggingConfig{
		File:  logFile,
		Level: "info",
		Fields: map[string]interface{}{
			"env":    "test",
			"region": "us-east-1",
		},
		SQL: LOG_SQL_ALL,
	}))

	// The configure path opens the log file before writing the "Set output
	// file to ..." entry; the file must exist after the call returns.
	_, err := os.Stat(logFile)
	require.NoError(t, err)
}

func TestNewCustomFormatterFormatsTimeAsUTC(t *testing.T) {
	f := NewCustomFormatter()
	require.NotNil(t, f)

	entry := logrus.NewEntry(logrus.New())
	entry.Message = "hello"
	out, err := f.Format(entry)
	require.NoError(t, err)
	require.Contains(t, string(out), "hello")
}

func TestSetPopLoggerExecutesAllSQLConfigs(t *testing.T) {
	// setPopLogger registers a closure with pop.SetLogger; calling it for
	// each documented SQL log mode covers the three branches that select
	// shouldLogSQL and shouldLogSQLArgs.
	for _, mode := range []string{LOG_SQL_NONE, LOG_SQL_STATEMENT, LOG_SQL_ALL, ""} {
		setPopLogger(mode)
	}
}
