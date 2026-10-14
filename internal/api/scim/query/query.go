package query

import (
	"encoding/json"
	"regexp"
	"slices"

	"github.com/supabase-community/scim-go/pkg/core"
)

func primary(keys []string) string {
	return path{"$", keys[:len(keys)-2]}.String() + "[*] ? (@.primary == true)." + literal(keys[len(keys)-1])
}

func resolved(references []Reference, parent, attribute *core.Attribute) bool {
	return slices.ContainsFunc(references, func(reference Reference) bool {
		return reference.attribute == parent && reference.computed(attribute.Name)
	})
}

func literal(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

func pattern(value any, suffix string) string {
	s, _ := value.(string)
	return literal(regexp.QuoteMeta(s) + suffix)
}
