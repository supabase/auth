package observability

import (
	"fmt"
	"net/http"
	"time"

	chimiddleware "github.com/go-chi/chi/middleware"
	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/utilities"
)

func NewStructuredLogger(logger *logrus.Logger, config *conf.GlobalConfiguration) func(next http.Handler) http.Handler {
	return chimiddleware.RequestLogger(&structuredLogger{logger, config})
}

type structuredLogger struct {
	Logger *logrus.Logger
	Config *conf.GlobalConfiguration
}

func (l *structuredLogger) NewLogEntry(r *http.Request) chimiddleware.LogEntry {
	referrer := utilities.GetReferrer(r, l.Config)
	e := &logEntry{Entry: logrus.NewEntry(l.Logger)}
	logFields := logrus.Fields{
		"component":   "api",
		"method":      r.Method,
		"path":        r.URL.Path,
		"remote_addr": utilities.GetIPAddress(r),
		"referer":     referrer,
	}

	if reqID := utilities.GetRequestID(r.Context()); reqID != "" {
		logFields["request_id"] = reqID
	}

	e.Entry = e.Entry.WithFields(logFields)
	e.Entry.Info("request started")
	return e
}

// logEntry implements the chiMiddleware.LogEntry interface
type logEntry struct {
	Entry *logrus.Entry
}

func (e *logEntry) Write(status, bytes int, elapsed time.Duration) {
	entry := e.Entry.WithFields(logrus.Fields{
		"status":   status,
		"duration": elapsed.Nanoseconds(),
	})
	entry.Info("request completed")
	e.Entry = entry
}

func (e *logEntry) Panic(v interface{}, stack []byte) {
	entry := e.Entry.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	})
	entry.Error("request panicked")
	e.Entry = entry
}

func GetLogEntry(r *http.Request) *logEntry {
	l, _ := chimiddleware.GetLogEntry(r).(*logEntry)
	if l == nil {
		return &logEntry{Entry: logrus.NewEntry(logrus.StandardLogger())}
	}
	return l
}

func LogEntrySetField(r *http.Request, key string, value interface{}) {
	if l, ok := r.Context().Value(chimiddleware.LogEntryCtxKey).(*logEntry); ok {
		l.Entry = l.Entry.WithField(key, value)
	}
}

func LogEntrySetFields(r *http.Request, fields logrus.Fields) {
	if l, ok := r.Context().Value(chimiddleware.LogEntryCtxKey).(*logEntry); ok {
		l.Entry = l.Entry.WithFields(fields)
	}
}
