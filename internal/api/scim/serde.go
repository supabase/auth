package scim

import (
	"encoding/json"
	"io"
)

func ToJSON[T any](w io.Writer, item T) error {
	return json.NewEncoder(w).Encode(item)
}

func FromJSON[T any](reader io.Reader) (T, error) {
	var item T
	return item, json.NewDecoder(reader).Decode(&item)
}
