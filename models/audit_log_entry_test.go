package models

import (
	"encoding/json"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/netlify/gotrue/conf"
	"github.com/netlify/gotrue/storage"
	"github.com/netlify/gotrue/storage/test"
	"github.com/netlify/gotrue/utilities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type AuditLogEntryTestSuite struct {
	suite.Suite
	db *storage.Connection
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
		db: conn,
	}
	defer ts.db.Close()

	suite.Run(t, ts)
}

func (ts *AuditLogEntryTestSuite) TestInsertAuditLogEntry() {
	u := ts.createUserWithEmail("test@example.com")

	err := NewAuditLogEntry(ts.db, ts.db, uuid.Nil, u, UserSignedUpAction, nil)
	require.NoError(ts.T(), err)

	logs, err := FindAuditLogEntries(ts.db, uuid.Nil, make([]string, 0), "", nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), logs, 1)

	entry := logs[0]
	assert.Equal(ts.T(), uuid.Nil, entry.InstanceID)
	assert.Equal(ts.T(), "test@example.com", entry.Payload["actor_username"])
	assert.Equal(ts.T(), u.ID.String(), entry.Payload["actor_id"])
	assert.Equal(ts.T(), string(UserSignedUpAction), entry.Payload["action"])
}

func (ts *AuditLogEntryTestSuite) TestInsertAuditLogEntryWithRejection() {
	u := ts.createUserWithEmail("test@example.com")

	// Add trigger which rejects audit log entries except `AuditLogEntryRejectedAction`.
	err := ts.db.RawQuery(`
		drop trigger if exists reject_audit_log_entries on auth.audit_log_entries;
		drop function if exists auth.reject_audit_log_entries;
		create function auth.reject_audit_log_entries() returns trigger as $$
			begin
				if (new.payload->>'action') != 'audit_log_entry_rejected' then
					raise sqlstate 'PT403' using
						message = 'Custom error message',
						detail = 'Custom detail',
						hint = 'Custom hint';
				end if;
				return NEW;
			end;
		$$ language plpgsql stable;

		create trigger reject_audit_log_entries
			after insert on auth.audit_log_entries
			for each row execute function auth.reject_audit_log_entries();
	`).Exec()
	require.NoError(ts.T(), err)

	// Inserting a new audit log entry should cause an error.
	err = NewAuditLogEntry(ts.db, ts.db, uuid.Nil, u, UserSignedUpAction, nil)
	require.Error(ts.T(), err)

	// Audit log should contain entry indicating rejection.
	logs, err := FindAuditLogEntries(ts.db, uuid.Nil, make([]string, 0), "", nil)
	require.NoError(ts.T(), err)
	require.Len(ts.T(), logs, 1)
	entry := logs[0]
	assert.Equal(ts.T(), uuid.Nil, entry.InstanceID)
	assert.Equal(ts.T(), "test@example.com", entry.Payload["actor_username"])
	assert.Equal(ts.T(), u.ID.String(), entry.Payload["actor_id"])
	assert.Equal(ts.T(), string(AuditLogEntryRejectedAction), entry.Payload["action"])

	var originalEntry AuditLogEntry
	bytes, err := json.Marshal(entry.Payload["original_entry"])
	require.NoError(ts.T(), err)
	err = json.Unmarshal(bytes, &originalEntry)
	require.NoError(ts.T(), err)

	// Audit log rejection entry should contain original entry information.
	assert.Equal(ts.T(), uuid.Nil, originalEntry.InstanceID)
	assert.Equal(ts.T(), "test@example.com", originalEntry.Payload["actor_username"])
	assert.Equal(ts.T(), u.ID.String(), originalEntry.Payload["actor_id"])
	assert.Equal(ts.T(), string(UserSignedUpAction), originalEntry.Payload["action"])

	var errorInfo utilities.PostgresError
	bytes, err = json.Marshal(entry.Payload["error"])
	require.NoError(ts.T(), err)
	err = json.Unmarshal(bytes, &errorInfo)
	require.NoError(ts.T(), err)

	// Audit log rejection entry should contain error information.
	assert.Equal(ts.T(), "PT403", errorInfo.Code)
	assert.Equal(ts.T(), "Custom error message", errorInfo.Message)
	assert.Equal(ts.T(), "Custom detail", errorInfo.Detail)
	assert.Equal(ts.T(), "Custom hint", errorInfo.Hint)

	// Clear the custom trigger and function.
	err = ts.db.RawQuery(`
		drop trigger reject_audit_log_entries on auth.audit_log_entries;
		drop function auth.reject_audit_log_entries;
	`).Exec()
	require.NoError(ts.T(), err)
}

func (ts *AuditLogEntryTestSuite) createUserWithEmail(email string) *User {
	user, err := NewUser(uuid.Nil, email, "secret", "test", nil)
	require.NoError(ts.T(), err)

	err = ts.db.Create(user)
	require.NoError(ts.T(), err)

	return user
}
