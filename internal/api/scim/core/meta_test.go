package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

type exampleUser struct {
	id               string
	created, updated time.Time
}

func (s exampleUser) ResourceID() string                       { return s.id }
func (s exampleUser) Timestamps() (created, updated time.Time) { return s.created, s.updated }

func TestMeta(t *testing.T) {
	baseURL := "http://localhost:9999/scim/v2"

	t.Run("NewMeta", func(t *testing.T) {
		meta := NewMeta(baseURL, KindServiceProviderConfig)

		require.Equal(t, KindServiceProviderConfig.Name, meta.ResourceType)
		require.Equal(t, baseURL+"/ServiceProviderConfig", meta.Location)
		require.Zero(t, meta.Created)
		require.Zero(t, meta.LastModified)
	})

	t.Run("For", func(t *testing.T) {
		t.Run("locates the resource under its collection", func(t *testing.T) {
			resource := exampleUser{
				id:      uuid.Must(uuid.NewV4()).String(),
				created: time.Date(2026, 7, 21, 19, 41, 41, 0, time.UTC),
				updated: time.Date(2026, 7, 22, 8, 12, 3, 0, time.UTC),
			}

			meta := NewMeta(baseURL, KindUser).For(resource)

			require.Equal(t, KindUser.Name, meta.ResourceType)
			require.Equal(t, baseURL+"/Users/"+resource.id, meta.Location)
			require.Equal(t, resource.created, meta.Created)
			require.Equal(t, resource.updated, meta.LastModified)
		})

		t.Run("restates the timestamps of the resource in UTC", func(t *testing.T) {
			eastern := time.FixedZone("EST", -5*60*60)
			resource := exampleUser{
				id:      "2819c223",
				created: time.Date(2026, 7, 21, 19, 41, 41, 0, eastern),
				updated: time.Date(2026, 7, 22, 3, 12, 3, 0, eastern),
			}

			meta := NewMeta(baseURL, KindUser).For(resource)

			require.Equal(t, time.UTC, meta.Created.Location())
			require.Equal(t, time.UTC, meta.LastModified.Location())

			body, err := json.Marshal(meta)

			require.NoError(t, err)
			require.Contains(t, string(body), `"created":"2026-07-22T00:41:41Z"`)
			require.Contains(t, string(body), `"lastModified":"2026-07-22T08:12:03Z"`)
		})
	})

	t.Run("json.Marshal", func(t *testing.T) {
		t.Run("serializes to JSON correctly", func(t *testing.T) {
			body, err := json.Marshal(NewMeta(baseURL, KindServiceProviderConfig))

			require.NoError(t, err)
			require.JSONEq(t, `{
				"resourceType": "ServiceProviderConfig",
				"location": "http://localhost:9999/scim/v2/ServiceProviderConfig"
			}`, string(body))
		})

		t.Run("omits the location when it is empty", func(t *testing.T) {
			body, err := json.Marshal(Meta{ResourceType: "ServiceProviderConfig"})

			require.NoError(t, err)
			require.JSONEq(t, `{"resourceType": "ServiceProviderConfig"}`, string(body))
		})
	})
}
