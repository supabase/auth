package models

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/sbff"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type AuditLogEntryTestSuite struct {
	suite.Suite
	db     *storage.Connection
	config *conf.GlobalConfiguration
}

func (ts *AuditLogEntryTestSuite) SetupTest() {
	TruncateAll(ts.db)
}

func TestAuditLogEntry(t *testing.T) {
	globalConfig, err := conf.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)

	conn, err := test.SetupDBConnection(globalConfig)
	require.NoError(t, err)

	ts := &AuditLogEntryTestSuite{
		db:     conn,
		config: globalConfig,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *AuditLogEntryTestSuite) TestNewAuditLogEntryPopulatesIPFromRemoteAddr() {
	user, err := NewUser("", "audit-ip@example.com", "secret", "test", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user))

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.RemoteAddr = "203.0.113.42:1234"

	require.NoError(ts.T(), NewAuditLogEntry(ts.config.AuditLog, req, ts.db, user, LoginAction, nil))

	entries, err := FindAuditLogEntries(ts.db, nil, "", nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), entries, 1)
	require.Equal(ts.T(), "203.0.113.42", entries[0].IPAddress)
}

func (ts *AuditLogEntryTestSuite) TestNewAuditLogEntryPopulatesIPFromXForwardedFor() {
	user, err := NewUser("", "audit-xff@example.com", "secret", "test", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user))

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	require.NoError(ts.T(), NewAuditLogEntry(ts.config.AuditLog, req, ts.db, user, LoginAction, nil))

	entries, err := FindAuditLogEntries(ts.db, nil, "", nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), entries, 1)
	require.Equal(ts.T(), "203.0.113.99", entries[0].IPAddress)
}

func (ts *AuditLogEntryTestSuite) TestNewAuditLogEntryPopulatesIPFromSbForwardedFor() {
	user, err := NewUser("", "audit-sbff@example.com", "secret", "test", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.db.Create(user))

	securityConfig := conf.SecurityConfiguration{SbForwardedForEnabled: true}
	middleware := sbff.Middleware(&securityConfig, func(r *http.Request, err error) {})

	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		require.NoError(ts.T(), NewAuditLogEntry(ts.config.AuditLog, r, ts.db, user, LoginAction, nil))
	})

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.Header.Set(sbff.HeaderName, "203.0.113.77")

	middleware(handler).ServeHTTP(httptest.NewRecorder(), req)

	entries, err := FindAuditLogEntries(ts.db, nil, "", nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), entries, 1)
	require.Equal(ts.T(), "203.0.113.77", entries[0].IPAddress)
}
