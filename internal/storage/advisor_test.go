package storage

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAdvisorZeroChanges(t *testing.T) {
	advised := false

	advisor := Advisor{
		AdviseFunc: func(advisory Advisory) {
			advised = true
		},
		StatsFunc: func() sql.DBStats {
			return sql.DBStats{}
		},
		Interval: time.Millisecond,
	}

	advisor.setup(10 * time.Millisecond)

	require.Len(t, advisor.WaitDurationSamples, 10)
	require.Len(t, advisor.WaitCountSamples, 10)

	advisor.Stats = advisor.StatsFunc()

	for i := 0; i < 11; i += 1 {
		advisor.loop()
	}

	require.False(t, advised)
}

func TestAdvisorWaitDuration(t *testing.T) {
	advised := false

	dbStats := sql.DBStats{}

	advisor := Advisor{
		AdviseFunc: func(advisory Advisory) {
			advised = true
		},
		StatsFunc: func() sql.DBStats {
			return dbStats
		},
		Interval: time.Millisecond,
	}

	advisor.setup(10 * time.Millisecond)

	require.Len(t, advisor.WaitDurationSamples, 10)
	require.Len(t, advisor.WaitCountSamples, 10)

	advisor.Stats = advisor.StatsFunc()

	for i := 0; i < 3; i += 1 {
		dbStats.WaitDuration += advisor.Interval
		advisor.loop()
	}

	require.True(t, advised)
}

func TestAdvisorWaitCount(t *testing.T) {
	advised := false

	dbStats := sql.DBStats{}

	advisor := Advisor{
		AdviseFunc: func(advisory Advisory) {
			advised = true
		},
		StatsFunc: func() sql.DBStats {
			return dbStats
		},
		Interval: time.Millisecond,
	}

	advisor.setup(10 * time.Millisecond)

	require.Len(t, advisor.WaitDurationSamples, 10)
	require.Len(t, advisor.WaitCountSamples, 10)

	advisor.Stats = advisor.StatsFunc()

	for i := 0; i < 3; i += 1 {
		dbStats.WaitCount += 3
		advisor.loop()
	}

	require.True(t, advised)
}
