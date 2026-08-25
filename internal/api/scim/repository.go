package scim

import "context"

type Repository[T any] interface {
	Get(ctx context.Context, id string) (T, error)
}
