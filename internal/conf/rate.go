package conf

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/didip/tollbooth/v5"
	"github.com/didip/tollbooth/v5/limiter"
)

type Rate struct {
	Events   float64       `json:"events,omitempty"`
	OverTime time.Duration `json:"over_time,omitempty"`
}

func (r *Rate) EventsPerSecond() float64 {
	if int64(r.OverTime) == 0 {
		return r.Events
	}

	return r.Events / r.OverTime.Seconds()
}

func (r *Rate) DivideIfDefaultDuration(div float64) *Rate {
	if r.OverTime == time.Duration(0) {
		return &Rate{
			Events: r.Events / div,
		}
	}

	return r
}

func (r *Rate) CreateLimiter() *limiter.Limiter {
	overTime := r.OverTime
	if int64(overTime) == 0 {
		// if r.OverTime is not specified, i.e. the configuration specified just a single float64 number, the
		overTime = time.Hour
	}

	return tollbooth.NewLimiter(r.EventsPerSecond(), &limiter.ExpirableOptions{
		DefaultExpirationTTL: overTime,
	})
}

func (r *Rate) Decode(value string) error {
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		r.Events = f
		// r.OverTime remains 0 in this case
		return nil
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return fmt.Errorf("rate: value does not match rate syntax %q", value)
	}

	f, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return fmt.Errorf("rate: events part of rate value %q failed to parse as float64: %w", value, err)
	}

	d, err := time.ParseDuration(parts[1])
	if err != nil {
		return fmt.Errorf("rate: over-time part of rate value %q failed to parse as duration: %w", value, err)
	}

	r.Events = f
	r.OverTime = d

	return nil
}

func (r *Rate) String() string {
	if r.OverTime == 0 {
		return fmt.Sprintf("%f", r.Events)
	}

	return fmt.Sprintf("%f/%s", r.Events, r.OverTime.String())
}
