package mailer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWithValidated(t *testing.T) {
	ctx := context.Background()
	require.False(t, IsValidated(ctx, "new@example.com"))

	ctx = WithValidated(ctx, "new@example.com", "current@example.com")
	require.True(t, IsValidated(ctx, "new@example.com"))
	require.True(t, IsValidated(ctx, "current@example.com"))
	require.False(t, IsValidated(ctx, "other@example.com"))
}
