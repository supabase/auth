package query

import (
	"testing"
	"time"
	"unicode/utf8"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase/auth/internal/models"
)

const id = "2819c223-7f76-453a-919d-413861904646"

var provider = uuid.MustParse("00000000-0000-0000-0000-000000000001")

func TestEvaluatorSQL(t *testing.T) {
	users := core.Schemas{core.NewSchema(core.SchemaUser).With(core.UserAttributes()...), core.NewSchema(core.SchemaEnterpriseUser).With(core.EnterpriseUserAttributes()...)}
	groups := core.Schemas{core.NewSchema(core.SchemaGroup).With(core.GroupAttributes()...)}
	user := NewEvaluator(users, provider, "https://example.com/scim/v2/Users", Derived("groups", "Group", "members"))
	group := NewEvaluator(groups, provider, "https://example.com/scim/v2/Groups", Stored("members", "User", "Group"))
	userName := `lower(resource ->> 'userName') COLLATE "C"`

	for _, test := range []struct {
		schemas   core.Schemas
		evaluator protocol.Evaluator[Clause]
		filter    string
		sql       string
		args      []any
	}{
		{users, user, `userName eq "Alice@Example.com"`, "(" + userName + ") IS NOT NULL AND " + userName + " = lower(?)", []any{"Alice@Example.com"}},
		{users, user, `userName sw "Ali"`, userName + " >= lower(?) AND " + userName + " < (lower(?) || ?)", []any{"Ali", "Ali", string(utf8.MaxRune)}},
		{users, user, `userName gt "a"`, "search @@ lower(?)::jsonpath", []any{`$."userName" > "a"`}},
		{users, user, `externalId eq "Ext-1"`, `((resource ->> 'externalId') COLLATE "C") IS NOT NULL AND (resource ->> 'externalId') COLLATE "C" = ?`, []any{"Ext-1"}},
		{users, user, `externalId sw "Ext"`, "(search @@ lower(?)::jsonpath AND resource @@ ?::jsonpath)", []any{`$."externalId" starts with "Ext"`, `$."externalId" starts with "Ext"`}},
		{users, user, `externalId gt "Ext"`, "resource @@ ?::jsonpath", []any{`$."externalId" > "Ext"`}},
		{users, user, `title pr`, "search @@ lower(?)::jsonpath", []any{`exists($."title" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`}},
		{users, user, `title eq "Boss" and title eq "Chief"`, "search @@ lower(?)::jsonpath", []any{`($."title" == "Boss" && $."title" == "Chief")`}},
		{users, user, `title eq "Boss" or title eq "Chief"`, "search @@ lower(?)::jsonpath", []any{`($."title" == "Boss" || $."title" == "Chief")`}},
		{users, user, `not (title eq "Boss")`, "search @@ lower(?)::jsonpath", []any{`!($."title" == "Boss")`}},
		{users, user, `title eq "Boss" and userName eq "a"`, "(search @@ lower(?)::jsonpath AND (" + userName + ") IS NOT NULL AND " + userName + " = lower(?))", []any{`$."title" == "Boss"`, "a"}},
		{users, user, `title eq "Boss" or userName eq "a"`, "(search @@ lower(?)::jsonpath OR (" + userName + ") IS NOT NULL AND " + userName + " = lower(?))", []any{`$."title" == "Boss"`, "a"}},
		{users, user, `not (userName eq "a")`, "NOT ((" + userName + ") IS NOT NULL AND " + userName + " = lower(?))", []any{"a"}},
		{users, user, `name.familyName co "Sm.ith"`, "search @@ lower(?)::jsonpath", []any{`$."name"."familyName" like_regex "Sm\\.ith"`}},
		{users, user, `emails.value ew "@Example.com"`, "search @@ lower(?)::jsonpath", []any{`$."emails"."value" like_regex "@Example\\.com$"`}},
		{users, user, `emails pr`, "search @@ lower(?)::jsonpath", []any{`exists($."emails" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`}},
		{users, user, `emails[type eq "work" and not (value pr)]`, "search @@ lower(?)::jsonpath", []any{`exists($."emails"[*] ? ((@."type" == "work" && !(exists(@."value" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))))))`}},
		{users, user, `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "42"`, "search @@ lower(?)::jsonpath", []any{`$."urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"."employeeNumber" == "42"`}},
		{users, user, `active eq true`, "search @@ lower(?)::jsonpath", []any{`$."active" == true`}},
		{users, user, `groups.value eq "` + id + `"`, walk("chain.id = ?::uuid"), []any{"members", provider.String(), id, "members", models.SCIMMaxDepth}},
		{users, user, `groups.value ne "nope"`, "(" + walk("true") + " OR NOT (" + walk("TRUE") + "))", []any{"members", provider.String(), "members", models.SCIMMaxDepth, "members", provider.String(), "members", models.SCIMMaxDepth}},
		{users, user, `groups[value ne "` + id + `"]`, walk("chain.id <> ?::uuid"), []any{"members", provider.String(), id, "members", models.SCIMMaxDepth}},
		{users, user, `nickName ne "Al"`, "search @@ lower(?)::jsonpath", []any{`($."nickName" != "Al" || !(exists($."nickName" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))))`}},
		{users, user, `externalId ne "Ext"`, "(resource @@ ?::jsonpath OR search @@ lower(?)::jsonpath)", []any{`$."externalId" != "Ext"`, `!(exists($."externalId" ? (@.type() != "null" && !(@.type() == "string" && @ == ""))))`}},
		{users, user, `emails[value ne "x"]`, "search @@ lower(?)::jsonpath", []any{`exists($."emails"[*] ? ((@."value" != "x" || !(exists(@."value" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))))))`}},
		{users, user, `nickName ne null`, "search @@ lower(?)::jsonpath", []any{`exists($."nickName" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`}},
		{users, user, `nickName eq null`, "search @@ lower(?)::jsonpath", []any{`!(exists($."nickName" ? (@.type() != "null" && !(@.type() == "string" && @ == ""))))`}},
		{users, user, `groups eq null`, "NOT (" + walk("TRUE") + ")", []any{"members", provider.String(), "members", models.SCIMMaxDepth}},
		{users, user, `id eq null`, "NOT (TRUE)", nil},
		{users, user, `userName sw null`, "false", nil},
		{users, user, `title co null`, "false", nil},
		{users, user, `title ew null`, "false", nil},
		{users, user, `meta.created gt null`, "false", nil},
		{users, user, `groups[value eq "` + id + `"]`, walk("chain.id = ?::uuid"), []any{"members", provider.String(), id, "members", models.SCIMMaxDepth}},
		{users, user, `groups pr`, walk("TRUE"), []any{"members", provider.String(), "members", models.SCIMMaxDepth}},
		{users, user, `id eq "` + id + `"`, "id = ?::uuid", []any{id}},
		{users, user, `id eq "nope"`, "false", nil},
		{users, user, `id ne "nope"`, "true", nil},
		{users, user, `id pr`, "TRUE", nil},
		{users, user, `meta pr`, "TRUE", nil},
		{users, user, `meta.location eq "https://example.com/scim/v2/Users/` + id + `"`, "id = ?::uuid", []any{id}},
		{users, user, `meta.location eq "https://example.org/` + id + `"`, "false", nil},
		{users, user, `meta.version eq "W/\"1700000000000000\""`, "updated_at = ?", []any{time.UnixMicro(1700000000000000).UTC()}},
		{users, user, `meta.version ne "bad"`, "true", nil},
		{users, user, `meta.version eq "W/\"-300000000000000000\""`, "false", nil},
		{users, user, `meta.lastModified gt "2026-01-01T00:00:00Z"`, "updated_at > ?", []any{time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}},
		{users, user, `meta.resourceType eq "User"`, "resource_type = ?", []any{"User"}},
		{groups, group, `displayName eq "Eng"`, "search @@ lower(?)::jsonpath", []any{`$."displayName" == "Eng"`}},
		{groups, group, `members.value eq "` + id + `"`, edge("edge.target_id = ?::uuid"), []any{"members", id}},
		{groups, group, `members[type eq "User" and value eq "` + id + `"]`, edge("(lower(target.resource_type) = lower(?) AND edge.target_id = ?::uuid)"), []any{"members", "User", id}},
		{groups, group, `members.value ne "` + id + `"`, "(" + edge("edge.target_id <> ?::uuid") + " OR NOT (" + edge("TRUE") + "))", []any{"members", id, "members"}},
		{groups, group, `members pr`, edge("TRUE"), []any{"members"}},
		{groups, group, `not (members pr)`, "NOT (" + edge("TRUE") + ")", []any{"members"}},
		{groups, group, `displayName eq "Eng" or members.value eq "` + id + `"`, "(search @@ lower(?)::jsonpath OR " + edge("edge.target_id = ?::uuid") + ")", []any{`$."displayName" == "Eng"`, "members", id}},
	} {
		t.Run(test.filter, func(t *testing.T) {
			clause, err := protocol.Filter(test.schemas, test.filter, test.evaluator)
			require.NoError(t, err)
			sql, args := clause.SQL()
			require.Equal(t, test.sql, sql)
			require.Equal(t, test.args, args)
		})
	}

	for filter, message := range map[string]string{
		`groups.display pr`:    `scim: 400 invalidFilter: "groups.display" cannot be filtered`,
		`groups.value sw "a"`:  `scim: 400 invalidFilter: "groups.value" supports only eq and ne`,
		`groups[value sw "a"]`: `scim: 400 invalidFilter: "groups.value" supports only eq and ne`,
		`id sw "a"`:            `scim: 400 invalidFilter: "id" supports only eq, ne, gt, ge, lt and le`,
	} {
		_, err := protocol.Filter(users, filter, user)
		require.EqualError(t, err, message)
	}
	_, err := protocol.Filter(groups, `members.value gt "x"`, group)
	require.EqualError(t, err, `scim: 400 invalidFilter: "members.value" supports only eq and ne`)

	widgets := core.Schemas{core.NewSchema("urn:example:Widget").With(core.NewAttribute("codes", core.TypeComplex).AsMultiValued().With(core.NewAttribute("value", core.TypeString).AsCaseExact()))}
	_, err = protocol.Filter(widgets, `codes[value eq "X"]`, NewEvaluator(widgets, provider, "https://example.com/scim/v2/Widgets"))
	require.EqualError(t, err, `scim: 400 invalidFilter: The specified filter syntax was invalid, or the specified attribute and filter comparison combination is not supported.`)
}

func walk(inner string) string {
	return `scim_resources.id = any(array(SELECT target_id FROM scim_resource_references WHERE attribute = ? AND source_id IN (WITH RECURSIVE walk (id, depth) AS (
		SELECT chain.id, 1 FROM scim_resources chain WHERE chain.sso_provider_id = ? AND chain.resource_type = 'Group' AND chain.deleted_at IS NULL AND ` + inner + `
		UNION
		SELECT edge.target_id, walk.depth + 1 FROM walk JOIN scim_resource_references edge ON edge.source_id = walk.id AND edge.attribute = ? AND edge.target_type = 'Group' WHERE walk.depth < ?
	) SELECT DISTINCT id FROM walk)))`
}

func edge(inner string) string {
	return "EXISTS (SELECT 1 FROM scim_resource_references edge JOIN scim_resources target ON target.id = edge.target_id AND target.deleted_at IS NULL WHERE edge.source_id = scim_resources.id AND edge.attribute = ? AND " + inner + ")"
}
