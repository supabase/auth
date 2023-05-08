package models_test

import (
	"testing"

	"github.com/gobuffalo/pop/v6"
	"github.com/stretchr/testify/assert"
	"github.com/supabase/gotrue/internal/models"
)

func TestTableNameNamespacing(t *testing.T) {
	cases := []struct {
		expected string
		value    interface{}
	}{
		{expected: "audit_log_entries", value: []*models.AuditLogEntry{}},
		{expected: "refresh_tokens", value: []*models.RefreshToken{}},
		{expected: "users", value: []*models.User{}},
	}

	for _, tc := range cases {
		m := &pop.Model{Value: tc.value}
		assert.Equal(t, tc.expected, m.TableName())
	}
}
