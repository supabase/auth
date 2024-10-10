package conf

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const defaultOverTime = time.Hour

type Rate struct {
	Events   float64       `json:"events,omitempty"`
	OverTime time.Duration `json:"over_time,omitempty"`
}

func (r *Rate) EventsPerSecond() float64 {
	d := r.OverTime
	if d == 0 {
		d = defaultOverTime
	}
	return r.Events / d.Seconds()
}

// Decode is used by envconfig to parse the env-config string to a Rate value.
func (r *Rate) Decode(value string) error {
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		r.Events = f
		r.OverTime = defaultOverTime
		return nil
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return fmt.Errorf("rate: value does not match rate syntax %q", value)
	}

	// 52 because the uint needs to fit in a float64
	e, err := strconv.ParseUint(parts[0], 10, 52)
	if err != nil {
		return fmt.Errorf("rate: events part of rate value %q failed to parse as uint64: %w", value, err)
	}

	d, err := time.ParseDuration(parts[1])
	if err != nil {
		return fmt.Errorf("rate: over-time part of rate value %q failed to parse as duration: %w", value, err)
	}

	r.Events = float64(e)
	r.OverTime = d
	return nil
}

func (r *Rate) String() string {
	if r.OverTime == 0 {
		return fmt.Sprintf("%f", r.Events)
	}
	return fmt.Sprintf("%d/%s", uint64(r.Events), r.OverTime.String())
}
