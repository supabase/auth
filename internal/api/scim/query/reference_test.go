package query

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
)

var inverses = map[Edge]Edge{{Type: "User", Attribute: "groups"}: {Type: "Group", Attribute: "members"}}

func TestReferencesFromCoreSchemas(t *testing.T) {
	users := core.Schemas{core.NewSchema(core.SchemaUser).With(core.UserAttributes()...), core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...)}
	groups := core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)}

	require.Equal(t, map[string]kind{"groups": inverse, string(core.SchemaEnterpriseUser) + ":manager": single}, paths(References("User", users, inverses)))
	members := References("Group", groups, inverses)
	require.Equal(t, map[string]kind{"members": multi}, paths(members))
	require.True(t, members[0].Nested())
}

func TestReferencesFromCustomSchemas(t *testing.T) {
	const extension = core.SchemaURI("urn:example:extension:Device")
	ref := func(name string, target core.ReferenceType, subs ...*core.Attribute) *core.Attribute {
		return core.NewAttribute(name, core.TypeComplex).With(append(subs, core.NewAttribute("value", core.TypeString), core.NewAttribute("$ref", core.TypeReference).Referencing(target, "Device"))...)
	}
	schemas := core.Schemas{
		core.NewSchema("urn:example:Device").With(core.NewAttribute("name", core.TypeString), ref("owner", "User", core.NewAttribute("display", core.TypeString).AsReadOnly())),
		core.NewSchema(extension).With(ref("approvers", "User").AsMultiValued()),
	}
	references := References("Device", schemas, inverses)
	approvers := string(extension) + ":approvers"
	require.Equal(t, map[string]kind{"owner": single, approvers: multi}, paths(references))
	require.False(t, references[1].Nested())

	sql := Select(references, protocol.Projection{}, map[string]string{"User": "https://x/Users", "Device": "https://x/Devices"})
	require.Contains(t, sql, `json_build_object('owner', (SELECT jsonb_strip_nulls(jsonb_build_object('$ref', CASE target.resource_type WHEN 'Device' THEN 'https://x/Devices/' WHEN 'User' THEN 'https://x/Users/' END || target.id, 'display', target.resource ->> 'displayName')) FROM scim_resources target`)
	require.Contains(t, sql, `(SELECT json_build_object('`+string(extension)+`', json_build_object('approvers', v)) FROM (SELECT (SELECT json_agg(`)
	require.Contains(t, sql, `attribute = '`+approvers+`'`)

	id := uuid.NewV7().String()
	clause, err := Where(schemas, "https://x/Devices", references, approvers+`.value eq "`+id+`"`)
	require.NoError(t, err)
	text, args := clause.SQL()
	require.Contains(t, text, "edge.attribute = ? AND edge.target_id = ?::uuid")
	require.Equal(t, []any{approvers, id}, args)

	_, _, err = Order(schemas, references, &protocol.SearchRequest{SortBy: approvers + ".value"})
	require.Error(t, err)

	document := core.Object{"owner": map[string]any{"value": id, "display": "Forged", "$ref": "x"}, string(extension): map[string]any{"approvers": []any{map[string]any{"value": id}}}}
	require.Equal(t, []any{map[string]any{"value": id}}, references[1].Get(document))
	for _, reference := range references {
		reference.Strip(document)
	}
	require.Equal(t, core.Object{"owner": map[string]any{"value": id}, string(extension): map[string]any{}}, document)
}

func paths(references []Reference) map[string]kind {
	kinds := map[string]kind{}
	for _, reference := range references {
		kinds[reference.Path()] = reference.kind
	}
	return kinds
}
