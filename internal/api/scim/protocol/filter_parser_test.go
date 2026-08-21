package protocol

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// The valid filters of RFC 7644, Section 3.4.2.2, Figure 2. An RFC is immutable,
// so this is the specification's own list rather than a paraphrase of it.
func TestParseFilterRFCExamples(t *testing.T) {
	examples := []string{
		`userName eq "bjensen"`,
		`name.familyName co "O'Malley"`,
		`userName sw "J"`,
		`urn:ietf:params:scim:schemas:core:2.0:User:userName sw "J"`,
		`title pr`,
		`meta.lastModified gt "2011-05-13T04:42:34Z"`,
		`meta.lastModified ge "2011-05-13T04:42:34Z"`,
		`meta.lastModified lt "2011-05-13T04:42:34Z"`,
		`meta.lastModified le "2011-05-13T04:42:34Z"`,
		`title pr and userType eq "Employee"`,
		`title pr or userType eq "Intern"`,
		`schemas eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`,
		`userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")`,
		`userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")`,
		`userType eq "Employee" and (emails.type eq "work")`,
		`userType eq "Employee" and emails[type eq "work" and value co "@example.com"]`,
		`emails[type eq "work" and value co "@example.com"] or ims[type eq "xmpp" and value co "@foo.com"]`,
	}

	for _, filter := range examples {
		t.Run(filter, func(t *testing.T) {
			got, err := ParseFilter(filter)
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

func TestParseFilterAST(t *testing.T) {
	cases := []struct {
		name   string
		filter string
		want   Filter
	}{
		{
			name:   "attribute equals string",
			filter: `userName eq "bjensen"`,
			want:   &AttrExpr{Path: AttrPath{Name: "userName"}, Op: OpEqual, Value: Value{Raw: "bjensen"}},
		},
		{
			name:   "uri qualified attribute path",
			filter: `urn:ietf:params:scim:schemas:core:2.0:User:userName sw "J"`,
			want: &AttrExpr{
				Path:  AttrPath{URI: "urn:ietf:params:scim:schemas:core:2.0:User", Name: "userName"},
				Op:    OpStartsWith,
				Value: Value{Raw: "J"},
			},
		},
		{
			name:   "sub attribute",
			filter: `name.familyName co "O'Malley"`,
			want:   &AttrExpr{Path: AttrPath{Name: "name", Sub: "familyName"}, Op: OpContains, Value: Value{Raw: "O'Malley"}},
		},
		{
			name:   "presence",
			filter: `title pr`,
			want:   &AttrExpr{Path: AttrPath{Name: "title"}, Op: OpPresent},
		},
		{
			name:   "and binds tighter than the operands read",
			filter: `title pr and userType eq "Employee"`,
			want: &LogicalExpr{
				Op:    LogicalAnd,
				Left:  &AttrExpr{Path: AttrPath{Name: "title"}, Op: OpPresent},
				Right: &AttrExpr{Path: AttrPath{Name: "userType"}, Op: OpEqual, Value: Value{Raw: "Employee"}},
			},
		},
		{
			name:   "or binds looser than and",
			filter: `a pr and b pr or c pr`,
			want: &LogicalExpr{
				Op: LogicalOr,
				Left: &LogicalExpr{
					Op:    LogicalAnd,
					Left:  &AttrExpr{Path: AttrPath{Name: "a"}, Op: OpPresent},
					Right: &AttrExpr{Path: AttrPath{Name: "b"}, Op: OpPresent},
				},
				Right: &AttrExpr{Path: AttrPath{Name: "c"}, Op: OpPresent},
			},
		},
		{
			name:   "not over a group",
			filter: `not (a pr or b pr)`,
			want: &NotExpr{Inner: &LogicalExpr{
				Op:    LogicalOr,
				Left:  &AttrExpr{Path: AttrPath{Name: "a"}, Op: OpPresent},
				Right: &AttrExpr{Path: AttrPath{Name: "b"}, Op: OpPresent},
			}},
		},
		{
			name:   "value path",
			filter: `emails[type eq "work"]`,
			want: &ValuePath{
				Path:   AttrPath{Name: "emails"},
				Filter: &AttrExpr{Path: AttrPath{Name: "type"}, Op: OpEqual, Value: Value{Raw: "work"}},
			},
		},
		{
			name:   "boolean compValue",
			filter: `active eq true`,
			want:   &AttrExpr{Path: AttrPath{Name: "active"}, Op: OpEqual, Value: Value{Raw: true}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFilter(tc.filter)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestParseFilterRejects(t *testing.T) {
	cases := []struct {
		name   string
		filter string
	}{
		{"empty", ``},
		{"whitespace only", `   `},
		{"missing value", `userName eq`},
		{"unknown operator", `userName xx "a"`},
		{"dangling and", `userName eq "a" and`},
		{"unbalanced open paren", `(userName eq "a"`},
		{"unbalanced close paren", `userName eq "a")`},
		{"unbalanced bracket", `emails[type eq "work"`},
		{"attribute path must start with a letter", `1name eq "a"`},
		{"bare word is not a filter", `userName`},
		{"unterminated string", `userName eq "a`},
		{"trailing tokens", `userName eq "a" userName eq "b"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFilter(tc.filter)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrInvalidFilter("")),
				"want ErrInvalidFilter, got %v", err)
		})
	}
}
