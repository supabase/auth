package scim

import "time"

type scimUser struct {
	ID        string    `db:"id"`
	Resource  []byte    `db:"resource"`
	Active    bool      `db:"active"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (scimUser) TableName() string {
	return "scim_users"
}
