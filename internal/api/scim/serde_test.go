package scim

import (
	"encoding/json"
	"io"
)

func FromJSON[T any](reader io.Reader) (T, error) {
	var item T
	return item, json.NewDecoder(reader).Decode(&item)
}
