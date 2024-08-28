package conf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRateDecode(t *testing.T) {
	r := Rate{}

	r = Rate{}
	require.NoError(t, r.Decode("123.0"))
	require.Equal(t, r, Rate{Events: 123.0, OverTime: 0})

	r = Rate{}
	require.NoError(t, r.Decode("123.0/24h"))
	require.Equal(t, r, Rate{Events: 123.0, OverTime: 24 * time.Hour})

	r = Rate{}
	require.Error(t, r.Decode("not a number"))

	r = Rate{}
	require.Error(t, r.Decode("123/456/789"))

	r = Rate{}
	require.Error(t, r.Decode("123/text"))
}
