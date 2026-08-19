package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttribute(t *testing.T) {
	t.Run("suggests the canonical values a client may send", func(t *testing.T) {
		attribute := NewAttribute("type", TypeString, "A label indicating the attribute's function.").
			Suggesting("work", "home", "other")

		body, err := json.Marshal(attribute)

		require.NoError(t, err)
		require.Contains(t, string(body), `"canonicalValues":["work","home","other"]`)
	})
}
