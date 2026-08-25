package core

import "time"

type Resource interface {
	ResourceID() string
	Timestamps() (created, updated time.Time)
}
