package conf

import (
	"time"
)

// Upper bounds for goroutines to prevent a bad config value from taking down
// the server.
var workerMaxCountPerCPU = 128

type WorkerConfiguration struct {

	// When set to true (default: false) workers will be started to handle
	// blocking tasks. If disabled no workers are started and blocking tasks
	// continue to work as they did before.
	Enabled bool `json:"enabled,omitempty" split_words:"true" default:"false"`

	// How many workers are started per CPU (runtime.NumCPU()), 32 by default.
	CountPerCPU      int           `split_words:"true" default:"32"`
	ShutdownDuration time.Duration `split_words:"true" default:"10s"`

	// TODO(cstockton): As we add more background tasks we may want to add:
	//
	//   Tasks TasksConfiguration `split_words:"true"
	//
	// Since some tasks such as sending Email or SMS may be more important than
	// others, so a way to configure a minimum worker pool size will help slow
	// but less important tasks from dominating important paths such as signup.
}

func (o *WorkerConfiguration) Validate() error {
	if o.CountPerCPU <= 0 {
		o.CountPerCPU = 1
	}
	if o.CountPerCPU > workerMaxCountPerCPU {
		o.CountPerCPU = workerMaxCountPerCPU
	}
	return nil
}
