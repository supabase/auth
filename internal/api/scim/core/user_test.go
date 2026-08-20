package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUser(t *testing.T) {
	created := time.Date(2026, 7, 21, 19, 41, 41, 0, time.UTC)
	lastModified := time.Date(2026, 7, 22, 8, 12, 3, 0, time.UTC)

	user := User{
		Schemas:    []SchemaURI{SchemaUser},
		ID:         "2819c223-7f76-453a-919d-413861904646",
		ExternalID: "701984",
		UserName:   "bjensen@example.com",
		Name:       Name{Formatted: "Ms. Barbara J Jensen", FamilyName: "Jensen", GivenName: "Barbara"},
		Emails:     []Email{{Value: "bjensen@example.com", Primary: true}},
		Active:     new(true),
		Meta: Meta{
			ResourceType: KindUser.Name,
			Created:      created,
			LastModified: lastModified,
			Location:     "http://localhost:9999/scim/v2/Users/2819c223-7f76-453a-919d-413861904646",
		},
	}

	t.Run("serializes to JSON correctly", func(t *testing.T) {
		body, err := json.Marshal(user)

		require.NoError(t, err)
		require.JSONEq(t, `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"id": "2819c223-7f76-453a-919d-413861904646",
			"externalId": "701984",
			"userName": "bjensen@example.com",
			"name": {"formatted": "Ms. Barbara J Jensen", "familyName": "Jensen", "givenName": "Barbara"},
			"emails": [{"value": "bjensen@example.com", "primary": true}],
			"active": true,
			"meta": {
				"resourceType": "User",
				"created": "2026-07-21T19:41:41Z",
				"lastModified": "2026-07-22T08:12:03Z",
				"location": "http://localhost:9999/scim/v2/Users/2819c223-7f76-453a-919d-413861904646"
			}
		}`, string(body))
	})

	t.Run("round-trips a deactivated user", func(t *testing.T) {
		var decoded User
		require.NoError(t, json.Unmarshal([]byte(`{"userName":"bjensen","active":false}`), &decoded))

		body, err := json.Marshal(decoded)

		require.NoError(t, err)
		require.Contains(t, string(body), `"active":false`)
	})
}
