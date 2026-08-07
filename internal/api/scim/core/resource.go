package core

import "time"

type Resource interface {
	ResourceID() string
	ResourceType() ResourceType
	Timestamps() (created, updated time.Time)
}
