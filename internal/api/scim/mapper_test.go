package scim

import (
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func TestUserMapper(t *testing.T) {
	id := uuid.Must(uuid.FromString("2819c223-7f76-453a-919d-413861904646"))
	createdAt := time.Date(2026, 7, 21, 19, 41, 41, 0, time.UTC)
	updatedAt := time.Date(2026, 7, 22, 8, 12, 3, 0, time.UTC)

	newModel := func(email string, claims map[string]interface{}) models.ProvisionedUser {
		in := models.ProvisionedUser{
			User: &models.User{
				ID:        id,
				Email:     storage.NullString(email),
				CreatedAt: createdAt,
				UpdatedAt: updatedAt,
			},
		}
		if claims != nil {
			in.Identity = &models.Identity{IdentityData: claims}
		}
		return in
	}

	mapper := NewUserMapper("http://localhost:9999/scim/v2")

	t.Run("maps a user onto the core User resource", func(t *testing.T) {
		user := mapper.MapFrom(newModel("bjensen@example.com", nil))

		require.Equal(t, []core.SchemaURI{core.SchemaUser}, user.Schemas)
		require.Equal(t, id.String(), user.ID)
		require.Equal(t, "bjensen@example.com", user.UserName)
		require.Equal(t, []core.Email{{Value: "bjensen@example.com", Primary: true}}, user.Emails)
		require.Equal(t, core.ResourceTypeUser, user.Meta.ResourceType)
	})

	t.Run("omits emails when the user has no email", func(t *testing.T) {
		user := mapper.MapFrom(newModel("", nil))

		require.Empty(t, user.UserName)
		require.Nil(t, user.Emails)
	})

	t.Run("builds the location from the base URL", func(t *testing.T) {
		user := NewUserMapper("https://auth.example.com/scim/v2").MapFrom(newModel("bjensen@example.com", nil))

		require.Equal(t, "https://auth.example.com/scim/v2/Users/"+id.String(), user.Meta.Location)
	})

	t.Run("normalizes the timestamps to UTC", func(t *testing.T) {
		model := newModel("bjensen@example.com", nil)
		model.CreatedAt = createdAt.In(time.FixedZone("MDT", -6*60*60))

		user := mapper.MapFrom(model)

		require.Equal(t, time.UTC, user.Meta.Created.Location())
		require.True(t, user.Meta.Created.Equal(createdAt))
		require.Equal(t, updatedAt, user.Meta.LastModified)
	})

	t.Run("prefers the email the provider supplied over the user record", func(t *testing.T) {
		user := mapper.MapFrom(newModel("stale@example.com", map[string]interface{}{
			"email": "bjensen@example.com",
		}))

		require.Equal(t, "bjensen@example.com", user.UserName)
		require.Equal(t, []core.Email{{Value: "bjensen@example.com", Primary: true}}, user.Emails)
	})

	t.Run("falls back to the user record when the provider supplied no email", func(t *testing.T) {
		user := mapper.MapFrom(newModel("bjensen@example.com", map[string]interface{}{
			"sub": id.String(),
		}))

		require.Equal(t, "bjensen@example.com", user.UserName)
		require.Equal(t, []core.Email{{Value: "bjensen@example.com", Primary: true}}, user.Emails)
	})

	t.Run("prefers preferred_username for the userName", func(t *testing.T) {
		user := mapper.MapFrom(newModel("", map[string]interface{}{
			"preferred_username": "bjensen",
			"email":              "bjensen@example.com",
		}))

		require.Equal(t, "bjensen", user.UserName)
		require.Equal(t, []core.Email{{Value: "bjensen@example.com", Primary: true}}, user.Emails)
	})

	t.Run("maps the name components the provider supplied", func(t *testing.T) {
		user := mapper.MapFrom(newModel("", map[string]interface{}{
			"name":        "Ms. Barbara Jane Jensen, III",
			"family_name": "Jensen",
			"given_name":  "Barbara",
			"middle_name": "Jane",
		}))

		require.Equal(t, &core.Name{
			Formatted:  "Ms. Barbara Jane Jensen, III",
			FamilyName: "Jensen",
			GivenName:  "Barbara",
			MiddleName: "Jane",
		}, user.Name)
	})

	t.Run("omits the name when the provider supplied no components", func(t *testing.T) {
		require.Nil(t, mapper.MapFrom(newModel("bjensen@example.com", nil)).Name)
		require.Nil(t, mapper.MapFrom(newModel("bjensen@example.com", map[string]interface{}{
			"sub": id.String(),
		})).Name)
	})

	t.Run("ignores claims that are not strings", func(t *testing.T) {
		user := mapper.MapFrom(newModel("bjensen@example.com", map[string]interface{}{
			"email":       12345,
			"given_name":  []string{"Barbara"},
			"family_name": "Jensen",
		}))

		require.Equal(t, "bjensen@example.com", user.UserName)
		require.Equal(t, &core.Name{FamilyName: "Jensen"}, user.Name)
	})

	t.Run("satisfies the Mapper interface", func(t *testing.T) {
		var _ Mapper[models.ProvisionedUser, *core.User] = NewUserMapper("")
	})
}
