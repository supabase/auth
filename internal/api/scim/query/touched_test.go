package query

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/patch"
)

func TestTouches(t *testing.T) {
	const a, b = "0199e0a0-0000-7000-8000-000000000001", "0199e0a0-0000-7000-8000-000000000002"
	manager := string(core.SchemaEnterpriseUser) + ":manager"
	groups := References("Group", core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)}, inverses)
	users := References("User", core.Schemas{core.NewSchema(core.SchemaUser).With(core.UserAttributes()...), core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...)}, inverses)
	op := func(op, path string, value any) patch.Operation {
		raw, _ := json.Marshal(value)
		if value == nil {
			raw = nil
		}
		return patch.Operation{Op: patch.Op(op), Path: path, Value: raw}
	}
	members := func(ids ...string) []map[string]string {
		out := []map[string]string{}
		for _, id := range ids {
			out = append(out, map[string]string{"value": id})
		}
		return out
	}

	for _, tc := range []struct {
		name       string
		references []Reference
		ops        []patch.Operation
		want       Touched
	}{
		{"displayName only", groups, []patch.Operation{op("replace", "displayName", "x")}, Touched{}},
		{"okta replace without path", groups, []patch.Operation{op("replace", "", map[string]any{"id": a, "displayName": "x"})}, Touched{}},
		{"add members", groups, []patch.Operation{op("Add", "members", members(a, "bogus"))}, Touched{"members": {a}}},
		{"remove by value", groups, []patch.Operation{op("remove", `members[value eq "`+b+`"]`, nil)}, Touched{"members": {b}}},
		{"add and remove", groups, []patch.Operation{op("add", "members", members(a)), op("remove", `members[value eq "`+b+`"]`, nil)}, Touched{"members": {a, b}}},
		{"remove a bogus value", groups, []patch.Operation{op("remove", `members[value eq "bogus"]`, nil)}, Touched{"members": {}}},
		{"remove all", groups, []patch.Operation{op("remove", "members", nil), op("add", "members", members(a))}, Touched{"members": nil}},
		{"remove by type", groups, []patch.Operation{op("remove", `members[type eq "User"]`, nil)}, Touched{"members": nil}},
		{"replace members", groups, []patch.Operation{op("add", "members", members(a)), op("replace", "members", members(b))}, Touched{"members": nil}},
		{"members in a value object", groups, []patch.Operation{op("add", "", map[string]any{"members": members(a)})}, Touched{"members": nil}},
		{"manager by path", users, []patch.Operation{op("replace", manager+".value", a)}, Touched{manager: nil}},
		{"manager in a value object", users, []patch.Operation{op("replace", "", map[string]any{string(core.SchemaEnterpriseUser): map[string]any{"manager": map[string]any{"value": a}}})}, Touched{manager: nil}},
		{"user name", users, []patch.Operation{op("replace", "userName", "x")}, Touched{}},
		{"unknown urn falls back", users, []patch.Operation{op("replace", "urn:example:Unknown:thing", "x")}, nil},
		{"bad path falls back", groups, []patch.Operation{op("remove", "members[", nil)}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, Touches(tc.references, tc.ops))
		})
	}
}
