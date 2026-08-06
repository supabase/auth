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

	newModel := func(email string) *models.User {
		return &models.User{
			ID:        id,
			Email:     storage.NullString(email),
			CreatedAt: createdAt,
			UpdatedAt: updatedAt,
		}
	}

	mapper := NewUserMapper("http://localhost:9999/scim/v2")

	t.Run("maps a user onto the core User resource", func(t *testing.T) {
		user := mapper.MapFrom(newModel("bjensen@example.com"))

		require.Equal(t, []core.SchemaURI{core.SchemaUser}, user.Schemas)
		require.Equal(t, id.String(), user.ID)
		require.Equal(t, "bjensen@example.com", user.UserName)
		require.Equal(t, []core.Email{{Value: "bjensen@example.com", Primary: true}}, user.Emails)
		require.Equal(t, core.ResourceTypeUser, user.Meta.ResourceType)
	})

	t.Run("omits emails when the user has no email", func(t *testing.T) {
		user := mapper.MapFrom(newModel(""))

		require.Empty(t, user.UserName)
		require.Nil(t, user.Emails)
	})

	t.Run("builds the location from the base URL", func(t *testing.T) {
		user := NewUserMapper("https://auth.example.com/scim/v2").MapFrom(newModel("bjensen@example.com"))

		require.Equal(t, "https://auth.example.com/scim/v2/Users/"+id.String(), user.Meta.Location)
	})

	t.Run("normalizes the timestamps to UTC", func(t *testing.T) {
		model := newModel("bjensen@example.com")
		model.CreatedAt = createdAt.In(time.FixedZone("MDT", -6*60*60))

		user := mapper.MapFrom(model)

		require.Equal(t, time.UTC, user.Meta.Created.Location())
		require.True(t, user.Meta.Created.Equal(createdAt))
		require.Equal(t, updatedAt, user.Meta.LastModified)
	})

	t.Run("satisfies the Mapper interface", func(t *testing.T) {
		var _ Mapper[*models.User, *core.User] = NewUserMapper("")
	})
}
