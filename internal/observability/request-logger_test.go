package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
)

const apiTestConfig = "../../hack/test.env"

func TestLogger(t *testing.T) {
	var logBuffer bytes.Buffer
	config, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)

	config.Logging.Level = "info"
	require.NoError(t, ConfigureLogging(&config.Logging))

	// logrus should write to the buffer so we can check if the logs are output correctly
	logrus.SetOutput(&logBuffer)

	// add request id header
	config.API.RequestIDHeader = "X-Request-ID"
	addRequestIdHandler := AddRequestID(config)

	logHandler := NewStructuredLogger(logrus.StandardLogger(), config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "http://example.com/path", nil)
	req.Header.Add("X-Request-ID", "test-request-id")
	require.NoError(t, err)
	addRequestIdHandler(logHandler).ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var logs map[string]interface{}
	require.NoError(t, json.NewDecoder(&logBuffer).Decode(&logs))
	require.Equal(t, "api", logs["component"])
	require.Equal(t, http.MethodPost, logs["method"])
	require.Equal(t, "/path", logs["path"])
	require.Equal(t, "test-request-id", logs["request_id"])
	require.NotNil(t, logs["time"])
}

func TestExcludeHealthFromLogs(t *testing.T) {
	var logBuffer bytes.Buffer
	config, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)

	config.Logging.Level = "info"
	require.NoError(t, ConfigureLogging(&config.Logging))

	// logrus should write to the buffer so we can check if the logs are output correctly
	logrus.SetOutput(&logBuffer)

	logHandler := NewStructuredLogger(logrus.StandardLogger(), config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodGet, "http://example.com/health", nil)
	require.NoError(t, err)
	logHandler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	require.Empty(t, logBuffer)
}

func TestContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	le := &logEntry{Entry: logrus.NewEntry(logrus.StandardLogger())}
	{
		got := GetLogEntryFromContext(ctx)
		if got == le {
			t.Fatal("exp new log entry")
		}
	}

	ctx = SetLogEntryWithContext(ctx, le)
	{
		got := GetLogEntryFromContext(ctx)
		if got != le {
			t.Fatal("exp new log entry")
		}
	}
}

func TestNewLogEntry(t *testing.T) {
	le := NewLogEntry(logrus.NewEntry(logrus.StandardLogger()))
	require.NotNil(t, le)
	// NewLogEntry returns a chimiddleware.LogEntry; verify the underlying type
	// is the package's *logEntry so downstream casts in GetLogEntry work.
	_, ok := le.(*logEntry)
	require.True(t, ok, "expected NewLogEntry to return *logEntry")
}

func TestGetLogEntryFallback(t *testing.T) {
	// No log entry is attached to this request's context, so GetLogEntry
	// should return a fresh fallback entry rather than panic or nil.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := GetLogEntry(req)
	require.NotNil(t, got)
	require.NotNil(t, got.Entry)
}

func TestGetLogEntryReturnsAttachedEntry(t *testing.T) {
	want := &logEntry{Entry: logrus.NewEntry(logrus.StandardLogger())}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := SetLogEntryWithContext(req.Context(), want)
	req = req.WithContext(ctx)

	got := GetLogEntry(req)
	require.Same(t, want, got)
}

func TestLogEntrySetField(t *testing.T) {
	le := &logEntry{Entry: logrus.NewEntry(logrus.StandardLogger())}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(SetLogEntryWithContext(req.Context(), le))

	LogEntrySetField(req, "user_id", "abc-123")
	require.Equal(t, "abc-123", le.Entry.Data["user_id"])
}

func TestLogEntrySetFieldsMerges(t *testing.T) {
	le := &logEntry{Entry: logrus.NewEntry(logrus.StandardLogger())}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(SetLogEntryWithContext(req.Context(), le))

	LogEntrySetFields(req, logrus.Fields{
		"session": "s1",
		"trace":   "t1",
	})
	require.Equal(t, "s1", le.Entry.Data["session"])
	require.Equal(t, "t1", le.Entry.Data["trace"])
}

func TestLogEntrySetFieldNoLogEntryInContextIsNoop(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	require.NotPanics(t, func() {
		LogEntrySetField(req, "k", "v")
		LogEntrySetFields(req, logrus.Fields{"k": "v"})
	})
}

func TestLogEntryPanicWritesPanicAndStackFields(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})

	le := &logEntry{Entry: logrus.NewEntry(logger)}
	le.Panic("boom", []byte("fake-stack-trace"))

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
	require.Equal(t, "request panicked", out["msg"])
	require.Equal(t, "fake-stack-trace", out["stack"])
	require.Contains(t, out["panic"], "boom")
}
