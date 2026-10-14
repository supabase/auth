package store

import "uuid"

type Ancestor struct {
	SourceID uuid.UUID `db:"source_id"`
	Longest  int       `db:"longest"`
}
