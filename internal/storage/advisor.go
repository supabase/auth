package storage

import (
	"database/sql"
	"math"
	"time"

	"github.com/sirupsen/logrus"
)

type Advisor struct {
	DB       *sql.DB
	Interval time.Duration

	Stats         sql.DBStats
	LastAdvisedAt time.Time

	Iterations int

	WaitDurationSamples []time.Duration
	WaitCountSamples    []int64
}

func (a *Advisor) Start(observeDuration time.Duration) {
	nSamples := int(math.Round(observeDuration.Seconds() / a.Interval.Seconds()))

	a.Stats = a.DB.Stats()
	a.WaitDurationSamples = make([]time.Duration, nSamples)
	a.WaitCountSamples = make([]int64, nSamples)

	go func() {
		for {
			time.Sleep(a.Interval)
			a.loop()
		}
	}()
}

func (a *Advisor) loop() {
	a.Iterations += 1
	if a.Iterations < 0 {
		a.Iterations = 0
	}

	previousStats := a.Stats
	a.Stats = a.DB.Stats()

	a.WaitDurationSamples[a.Iterations%len(a.WaitDurationSamples)] = a.Stats.WaitDuration - previousStats.WaitDuration
	a.WaitCountSamples[a.Iterations%len(a.WaitCountSamples)] = a.Stats.WaitCount - previousStats.WaitCount

	advise := false

	longWaitDurationSamples := 0
	if a.Iterations >= len(a.WaitDurationSamples) {
		for _, sample := range a.WaitDurationSamples {
			if sample >= a.Interval {
				longWaitDurationSamples += 1
			}
		}

		// 1/3 of the observation time was spent waiting for over 1ms
		advise = longWaitDurationSamples >= (len(a.WaitDurationSamples) / 3)
	}

	over2WaitingSamples := 0
	if !advise && a.Iterations >= len(a.WaitCountSamples) {
		for _, sample := range a.WaitCountSamples {
			if sample > 2 {
				over2WaitingSamples += 1
			}
		}

		// 1/3 of the observation time we saw more than 2 goroutines waiting for a connection
		advise = over2WaitingSamples >= (len(a.WaitCountSamples) / 3)
	}

	if advise && time.Since(a.LastAdvisedAt) >= time.Hour {
		a.LastAdvisedAt = time.Now()

		logrus.WithFields(logrus.Fields{
			"component":                  "db.advisor",
			"long_wait_duration_samples": longWaitDurationSamples,
			"over_2_waiting_samples":     over2WaitingSamples,
		}).Warn("Suboptimal database connection pool settings detected! Consider doubling the max DB pool size configuration")
	}
}
