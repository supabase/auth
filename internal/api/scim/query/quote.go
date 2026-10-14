package query

import (
	"encoding/json"
	"regexp"
	"strings"
)

func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func literal(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func pattern(value any, suffix string) string {
	s, _ := value.(string)
	return literal(regexp.QuoteMeta(s) + suffix)
}
