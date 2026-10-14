package query

import (
	"strconv"
	"strings"
	"time"
)

func Version(t time.Time) string {
	return `W/"` + strconv.FormatInt(t.UnixMicro(), 10) + `"`
}

func VersionTime(version string) *time.Time {
	micros, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(version, `W/"`), `"`), 10, 64)
	if err != nil || micros < 0 {
		return nil
	}
	t := time.UnixMicro(micros).UTC()
	return &t
}
