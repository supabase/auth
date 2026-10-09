package query

import (
	"testing"
	"time"
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
		{users, user, `userName eq "Alice@Example.com"`, "(" + userName + ") IS NOT NULL AND " + userName + " = ?", []any{"alice@example.com"}},
		{users, user, `userName sw "Ali"`, userName + " >= ? AND " + userName + " < ?", []any{"ali", "alj"}},
		{users, user, `userName gt "a"`, "search @@ ?::jsonpath", []any{`$."username" > "a"`}},
		{users, user, `externalId eq "Ext-1"`, `((resource ->> 'externalId') COLLATE "C") IS NOT NULL AND (resource ->> 'externalId') COLLATE "C" = ?`, []any{"Ext-1"}},
		{users, user, `externalId sw "Ext"`, "(search @@ ?::jsonpath AND resource @@ ?::jsonpath)", []any{`$."externalid" starts with "ext"`, `$."externalId" starts with "Ext"`}},
		{users, user, `externalId gt "Ext"`, "resource @@ ?::jsonpath", []any{`$."externalId" > "Ext"`}},
		{users, user, `title pr`, "search @@ ?::jsonpath", []any{`exists($."title" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`}},
		{users, user, `title eq "Boss" and title eq "Chief"`, "search @@ ?::jsonpath", []any{`($."title" == "boss" && $."title" == "chief")`}},
		{users, user, `title eq "Boss" or title eq "Chief"`, "search @@ ?::jsonpath", []any{`($."title" == "boss" || $."title" == "chief")`}},
		{users, user, `not (title eq "Boss")`, "search @@ ?::jsonpath", []any{`!($."title" == "boss")`}},
		{users, user, `title eq "Boss" and userName eq "a"`, "(search @@ ?::jsonpath AND (" + userName + ") IS NOT NULL AND " + userName + " = ?)", []any{`$."title" == "boss"`, "a"}},
		{users, user, `title eq "Boss" or userName eq "a"`, "(search @@ ?::jsonpath OR (" + userName + ") IS NOT NULL AND " + userName + " = ?)", []any{`$."title" == "boss"`, "a"}},
		{users, user, `not (userName eq "a")`, "NOT ((" + userName + ") IS NOT NULL AND " + userName + " = ?)", []any{"a"}},
		{users, user, `name.familyName co "Sm.ith"`, "search @@ ?::jsonpath", []any{`$."name"."familyname" like_regex "sm\\.ith"`}},
		{users, user, `emails.value ew "@Example.com"`, "search @@ ?::jsonpath", []any{`$."emails"."value" like_regex "@example\\.com$"`}},
		{users, user, `emails pr`, "search @@ ?::jsonpath", []any{`exists($."emails" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))`}},
		{users, user, `emails[type eq "work" and not (value pr)]`, "search @@ ?::jsonpath", []any{`exists($."emails"[*] ? ((@."type" == "work" && !(exists(@."value" ? (@.type() != "null" && !(@.type() == "string" && @ == "")))))))`}},
		{users, user, `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "42"`, "search @@ ?::jsonpath", []any{`$."urn:ietf:params:scim:schemas:extension:enterprise:2.0:user"."employeenumber" == "42"`}},
		{users, user, `active eq true`, "search @@ ?::jsonpath", []any{`$."active" == true`}},
		{users, user, `groups.value eq "` + id + `"`, walk("chain.id = ?::uuid"), []any{"members", provider.String(), id, "members", models.SCIMMaxDepth}},
		{users, user, `groups.value ne "nope"`, walk("true"), []any{"members", provider.String(), "members", models.SCIMMaxDepth}},
		{users, user, `groups[value eq "` + id + `"]`, walk("chain.id = ?::uuid"), []any{"members", provider.String(), id, "members", models.SCIMMaxDepth}},
		{users, user, `groups pr`, walk("TRUE"), []any{"members", provider.String(), "members", models.SCIMMaxDepth}},
		{users, user, `id eq "` + id + `"`, "id = ?::uuid", []any{id}},
		{users, user, `id eq "nope"`, "false", nil},
		{users, user, `id ne "nope"`, "true", nil},
		{users, user, `id pr`, "TRUE", nil},
		{users, user, `meta.location eq "https://example.com/scim/v2/Users/` + id + `"`, "id = ?::uuid", []any{id}},
		{users, user, `meta.location eq "https://example.org/` + id + `"`, "false", nil},
		{users, user, `meta.version eq "W/\"1700000000000000\""`, "updated_at = ?", []any{time.UnixMicro(1700000000000000).UTC()}},
		{users, user, `meta.version ne "bad"`, "true", nil},
		{users, user, `meta.lastModified gt "2026-01-01T00:00:00Z"`, "updated_at > ?", []any{time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}},
		{users, user, `meta.resourceType eq "User"`, "resource_type = ?", []any{"User"}},
		{groups, group, `displayName eq "Eng"`, "search @@ ?::jsonpath", []any{`$."displayname" == "eng"`}},
		{groups, group, `members.value eq "` + id + `"`, edge("edge.target_id = ?::uuid"), []any{"members", id}},
		{groups, group, `members[type eq "User" and value eq "` + id + `"]`, edge("(lower(target.resource_type) = ? AND edge.target_id = ?::uuid)"), []any{"members", "user", id}},
		{groups, group, `members pr`, edge("TRUE"), []any{"members"}},
		{groups, group, `not (members pr)`, "NOT (" + edge("TRUE") + ")", []any{"members"}},
		{groups, group, `displayName eq "Eng" or members.value eq "` + id + `"`, "(search @@ ?::jsonpath OR " + edge("edge.target_id = ?::uuid") + ")", []any{`$."displayname" == "eng"`, "members", id}},
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
