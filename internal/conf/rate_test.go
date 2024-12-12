package conf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRateDecode(t *testing.T) {
	cases := []struct {
		str string
		eps float64
		exp Rate
		err string
	}{
		{str: "1800", eps: 0.5, exp: Rate{Events: 1800, OverTime: time.Hour}},
		{str: "1800.0", eps: 0.5, exp: Rate{Events: 1800, OverTime: time.Hour}},
		{str: "3600/1h", eps: 1, exp: Rate{Events: 3600, OverTime: time.Hour}},
		{str: "100/24h",
			eps: 0.0011574074074074073,
			exp: Rate{Events: 100, OverTime: time.Hour * 24}},
		{str: "", eps: 1, exp: Rate{},
			err: `rate: value does not match`},
		{str: "1h", eps: 1, exp: Rate{},
			err: `rate: value does not match`},
		{str: "/", eps: 1, exp: Rate{},
			err: `rate: events part of rate value`},
		{str: "/1h", eps: 1, exp: Rate{},
			err: `rate: events part of rate value`},
		{str: "3600.0/1h", eps: 1, exp: Rate{},
			err: `rate: events part of rate value "3600.0/1h" failed to parse`},
		{str: "100/", eps: 1, exp: Rate{},
			err: `rate: over-time part of rate value`},
		{str: "100/1", eps: 1, exp: Rate{},
			err: `rate: over-time part of rate value`},

		// zero events
		{str: "0/1h", eps: 0.0, exp: Rate{Events: 0, OverTime: time.Hour}},
		{str: "0/24h", eps: 0.0, exp: Rate{Events: 0, OverTime: time.Hour * 24}},
	}
	for idx, tc := range cases {
		var r Rate
		err := r.Decode(tc.str)
		require.Equal(t, tc.exp, r) // verify don't mutate r on errr
		t.Logf("tc #%v - duration str %v", idx, tc.str)
		if tc.err != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.err)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, tc.exp, r)
		require.Equal(t, tc.eps, r.EventsPerSecond())
	}
}
