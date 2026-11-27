package v0hooks

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/utilities"
)

func TestNewMetadataHookData(t *testing.T) {
	t.Run("carries the value the caller supplied", func(t *testing.T) {
		r := httptest.NewRequest("POST", "http://localhost/signup", nil)
		r = r.WithContext(utilities.WithHookData(r.Context(), "opaque-value"))

		meta := NewMetadata(r, BeforeUserCreated)
		require.Equal(t, "opaque-value", meta.HookData)
	})

	t.Run("is empty when the caller supplied none", func(t *testing.T) {
		r := httptest.NewRequest("POST", "http://localhost/signup", nil)

		meta := NewMetadata(r, BeforeUserCreated)
		require.Equal(t, "", meta.HookData)
	})

	// The compatibility guarantee: a payload for a request that carried no hook
	// data must serialise exactly as it did before this field existed, so that
	// hooks parsing it strictly do not begin to fail.
	t.Run("is absent from the payload when unset", func(t *testing.T) {
		r := httptest.NewRequest("POST", "http://localhost/signup", nil)

		out, err := json.Marshal(NewMetadata(r, BeforeUserCreated))
		require.NoError(t, err)
		require.False(t, strings.Contains(string(out), "hook_data"))
	})

	t.Run("is present in the payload when set", func(t *testing.T) {
		r := httptest.NewRequest("POST", "http://localhost/signup", nil)
		r = r.WithContext(utilities.WithHookData(r.Context(), "opaque-value"))

		out, err := json.Marshal(NewBeforeUserCreatedInput(r, nil))
		require.NoError(t, err)

		var got BeforeUserCreatedInput
		require.NoError(t, json.Unmarshal(out, &got))
		require.Equal(t, "opaque-value", got.Metadata.HookData)
	})

	// Every hook shares NewMetadata, so a value attached to a request that goes
	// on to send an email is visible there too. That is deliberate -- it is one
	// value per request, not one per hook.
	t.Run("reaches other hooks on the same request", func(t *testing.T) {
		r := httptest.NewRequest("POST", "http://localhost/otp", nil)
		r = r.WithContext(utilities.WithHookData(r.Context(), "opaque-value"))

		require.Equal(t, "opaque-value", NewMetadata(r, SendEmail).HookData)
		require.Equal(t, "opaque-value", NewAfterUserCreatedInput(r, nil).Metadata.HookData)
	})
}
