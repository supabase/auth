package utilities

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStringValue(t *testing.T) {
	empty := ""
	hello := "hello"
	tests := []struct {
		name string
		in   *string
		want string
	}{
		{
			name: "nil pointer returns empty string",
			in:   nil,
			want: "",
		},
		{
			name: "pointer to empty string returns empty string",
			in:   &empty,
			want: "",
		},
		{
			name: "pointer to non-empty string returns the value",
			in:   &hello,
			want: "hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, StringValue(tt.in))
		})
	}
}

func TestStringPtr(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		expectNil   bool
		wantPointee string
	}{
		{
			name:      "empty string returns nil",
			in:        "",
			expectNil: true,
		},
		{
			name:        "non-empty string returns pointer to that value",
			in:          "hello",
			wantPointee: "hello",
		},
		{
			name:        "string with whitespace and newline preserved",
			in:          "  hi\nthere  ",
			wantPointee: "  hi\nthere  ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StringPtr(tt.in)
			if tt.expectNil {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tt.wantPointee, *got)
		})
	}

	t.Run("returned pointer is independent of the input variable", func(t *testing.T) {
		s := "original"
		p := StringPtr(s)
		require.Equal(t, "original", *p)
		s = "mutated"
		require.Equal(t, "original", *p)
	})
}

func TestStringValueAndStringPtrRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "ascii", in: "hello"},
		{name: "with spaces", in: "with spaces"},
		{name: "with newline", in: "with\nnewline"},
		{name: "multibyte rune", in: "🦄"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.in, StringValue(StringPtr(tt.in)))
		})
	}
}
