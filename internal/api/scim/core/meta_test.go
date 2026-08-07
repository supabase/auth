package core

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
)

type resource struct {
	id               string
	created, updated time.Time
}

func (s resource) ResourceID() string { return s.id }
func (s resource) ResourceType() ResourceType {
	return ResourceType{Name: "Resource", Endpoint: "/Resources"}
}
func (s resource) Timestamps() (created, updated time.Time) { return s.created, s.updated }

func TestNewMeta(t *testing.T) {
	baseURL := "http://localhost:9999/scim/v2"
	id := uuid.Must(uuid.NewV4()).String()
	created := time.Date(2026, 7, 21, 19, 41, 41, 0, time.UTC)
	updated := time.Date(2026, 7, 22, 8, 12, 3, 0, time.UTC)

	t.Run("locates a resource that is its own endpoint", func(t *testing.T) {
		meta := NewMeta(baseURL, ResourceTypeServiceProviderConfig)

		require.Equal(t, ResourceTypeServiceProviderConfig.Name, meta.ResourceType)
		require.Equal(t, baseURL+"/ServiceProviderConfig", meta.Location)
		require.Zero(t, meta.Created)
		require.Zero(t, meta.LastModified)
	})

	t.Run("locates one resource of a collection", func(t *testing.T) {
		meta := NewMeta(baseURL, ResourceTypeUser).For(resource{
			id:      id,
			created: created,
			updated: updated,
		})

		require.Equal(t, ResourceTypeUser.Name, meta.ResourceType)
		require.Equal(t, baseURL+"/Users/"+id, meta.Location)
		require.Equal(t, created, meta.Created)
		require.Equal(t, updated, meta.LastModified)
	})

	t.Run("normalizes the timestamps to UTC", func(t *testing.T) {
		meta := NewMeta(baseURL, ResourceTypeUser).For(resource{
			id:      id,
			created: created.In(time.FixedZone("MDT", -6*60*60)),
			updated: updated.In(time.FixedZone("MDT", -6*60*60)),
		})

		require.Equal(t, time.UTC, meta.Created.Location())
		require.Equal(t, time.UTC, meta.LastModified.Location())
		require.True(t, meta.Created.Equal(created))
		require.True(t, meta.LastModified.Equal(updated))
	})

	t.Run("leaves the receiver untouched", func(t *testing.T) {
		collection := NewMeta(baseURL, ResourceTypeUser)

		first := collection.For(resource{id: "first"})
		second := collection.For(resource{id: "second"})

		require.Equal(t, baseURL+"/Users/first", first.Location)
		require.Equal(t, baseURL+"/Users/second", second.Location)
		require.Equal(t, baseURL+"/Users", collection.Location)
		require.Zero(t, collection.Created)
	})
}

func TestMeta(t *testing.T) {
	t.Run("serializes to JSON correctly", func(t *testing.T) {
		body, err := json.Marshal(Meta{
			ResourceType: "ServiceProviderConfig",
			Location:     "http://localhost:9999/scim/v2/ServiceProviderConfig",
		})

		require.NoError(t, err)
		require.JSONEq(t, `{
			"resourceType": "ServiceProviderConfig",
			"location": "http://localhost:9999/scim/v2/ServiceProviderConfig"
		}`, string(body))
	})

	t.Run("omits the location when it is empty", func(t *testing.T) {
		body, err := json.Marshal(Meta{ResourceType: "Example"})

		require.NoError(t, err)
		require.JSONEq(t, `{"resourceType": "Example"}`, string(body))
	})
}
