package query

import (
	"strconv"
	"strings"
	"time"
)

const MaxDepth = 8

func QuoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func VersionTime(version string) *time.Time {
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil || micros < 0 {
		return nil
	}
	t := time.UnixMicro(micros).UTC()
	return &t
}
