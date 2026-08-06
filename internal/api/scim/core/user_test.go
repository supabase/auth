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
		Name:       &Name{Formatted: "Ms. Barbara J Jensen", FamilyName: "Jensen", GivenName: "Barbara"},
		Emails:     []Email{{Value: "bjensen@example.com", Primary: true}},
		Active:     true,
		Meta: Meta{
			ResourceType: ResourceTypeUser,
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

	t.Run("omits the optional attributes when they are unset", func(t *testing.T) {
		user.Emails, user.Name, user.ExternalID = nil, nil, ""

		body, err := json.Marshal(user)

		require.NoError(t, err)
		require.NotContains(t, string(body), "emails")
		require.NotContains(t, string(body), "name")
		require.NotContains(t, string(body), "externalId")
	})

	t.Run("always reports active, so a deactivated user is not read as unknown", func(t *testing.T) {
		user.Active = false

		body, err := json.Marshal(user)

		require.NoError(t, err)
		require.Contains(t, string(body), `"active":false`)
	})
}
