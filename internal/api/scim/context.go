package scim

import "context"

type Key[T any] struct {
	name string
}

func NewKey[T any](name string) Key[T] {
	return Key[T]{name: name}
}

func (k Key[T]) String() string {
	return k.name
}

func (k Key[T]) With(ctx context.Context, value T) context.Context {
	return context.WithValue(ctx, k, value)
}

func (k Key[T]) From(ctx context.Context) T {
	value, _ := ctx.Value(k).(T)
	return value
}
