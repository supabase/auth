package core

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/supabase/auth/internal/api/scim/scimtest"
)

// These tests carry the JSON examples of RFC 7643, Section 8 through the types
// of this package and report what does not survive the trip. A list recorded
// here is what the package does not yet represent faithfully; shortening one
// is how a newly supported attribute is proven against the specification.
func TestRFC7643(t *testing.T) {
	t.Run("carries the minimal User of Section 8.1 whole", func(t *testing.T) {
		assert.Empty(t, scimtest.RoundTripDiff(t, scimtest.RFC7643MinimalUser, &User{}))
	})

	t.Run("carries the resource types of Section 8.6 whole", func(t *testing.T) {
		assert.Empty(t, scimtest.RoundTripDiff(t, scimtest.RFC7643ResourceTypes, &[]ResourceType{}))
	})

	t.Run("does not yet carry the full User of Section 8.2", func(t *testing.T) {
		assert.Equal(t, []string{
			"addresses",
			"displayName",
			"emails[0].type",
			"emails[1].primary",
			"emails[1].type",
			"groups",
			"ims",
			"locale",
			"name.honorificPrefix",
			"name.honorificSuffix",
			"nickName",
			"password",
			"phoneNumbers",
			"photos",
			"preferredLanguage",
			"profileUrl",
			"timezone",
			"title",
			"userType",
			"x509Certificates",
		}, scimtest.RoundTripDiff(t, scimtest.RFC7643FullUser, &User{}))
	})

	t.Run("does not yet carry the enterprise extension of Section 8.3", func(t *testing.T) {
		assert.Contains(t,
			scimtest.RoundTripDiff(t, scimtest.RFC7643EnterpriseUser, &User{}),
			string(SchemaEnterpriseUser))
	})

	t.Run("states a primary scheme where the configuration of Section 8.5 leaves it unsaid", func(t *testing.T) {
		assert.Equal(t,
			[]string{"authenticationSchemes[1].primary"},
			scimtest.RoundTripDiff(t, scimtest.RFC7643ServiceProviderConfiguration, &ServiceProviderConfig{}))
	})

	// Section 7 states an attribute characteristic only where it bears on the
	// attribute, so the schemas of Section 8.7 leave "caseExact" off a complex
	// attribute and "uniqueness" off most. Attribute states both regardless,
	// and Schema states "schemas" and "meta" that a bare schema definition
	// does not carry.
	t.Run("states attribute characteristics the schemas of Section 8.7 leave unsaid", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			stray []string
		}{
			{scimtest.RFC7643ResourceSchemas, []string{"canonicalValues", "caseExact", "schemas", "uniqueness"}},
			{scimtest.RFC7643ServiceProviderSchemas, []string{"caseExact", "meta", "schemas", "uniqueness"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, tc.stray, leaves(scimtest.RoundTripDiff(t, tc.name, &[]Schema{})))
			})
		}
	})
}

// leaves reduces a list of attribute paths to the distinct attribute names they
// end in, so that a repeated difference reads as one finding.
func leaves(paths []string) []string {
	seen := map[string]bool{}
	for _, path := range paths {
		parts := strings.Split(path, ".")
		seen[parts[len(parts)-1]] = true
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
