package utilities

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func TestSafeClose(t *testing.T) {
	tests := []struct {
		name      string
		closer    io.Closer
		closerErr error
	}{
		{
			name:      "happy path: Close returns nil",
			closerErr: nil,
		},
		{
			name:      "Close returns error: SafeClose must not panic",
			closerErr: errors.New("close failed"),
		},
		{
			name:   "io.NopCloser: SafeClose must not panic",
			closer: io.NopCloser(nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			closer := tt.closer
			if closer == nil {
				called := false
				closer = closerFunc(func() error {
					called = true
					return tt.closerErr
				})
				require.NotPanics(t, func() { SafeClose(closer) })
				require.True(t, called, "Close should have been invoked")
				return
			}
			require.NotPanics(t, func() { SafeClose(closer) })
		})
	}
}
