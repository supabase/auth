package query

import (
	"time"

	"github.com/supabase-community/scim-go/pkg/server"
)

func VersionTime(version string) *time.Time {
	t, ok := server.ParseWeakETag(version)
	if !ok {
		return nil
	}
	return &t
}
