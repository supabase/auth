package protocol

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/supabase/auth/internal/api/scim/core"
)

// SortOrder is the direction a sort runs in, per RFC 7644, Section 3.4.2.3.
type SortOrder string

const (
	SortAscending  SortOrder = "ascending"
	SortDescending SortOrder = "descending"
)

// SearchRequest is the query of RFC 7644, Section 3.4.3.
//
// The same parameters reach a provider two ways: as the query string of a GET,
// per Section 3.4.2, or as the body of a POST to "/.search". One type serves
// both, so a handler reads the client's intent the same way either way.
type SearchRequest struct {
	Schemas            []core.SchemaURI `json:"schemas,omitempty"`
	Attributes         []string         `json:"attributes,omitempty"`
	ExcludedAttributes []string         `json:"excludedAttributes,omitempty"`
	Filter             string           `json:"filter,omitempty"`
	SortBy             string           `json:"sortBy,omitempty"`
	SortOrder          SortOrder        `json:"sortOrder,omitempty"`
	StartIndex         int              `json:"startIndex,omitempty"`
	Count              int              `json:"count,omitempty"`
}

// Offset is the start index counted from zero, for a store that windows a
// result set that way. A start index the client never gave, or one before the
// first, is the first, per Table 6 of Section 3.4.2.4.
func (s *SearchRequest) Offset() int {
	if s.StartIndex < 1 {
		return 0
	}
	return s.StartIndex - 1
}

func (s *SearchRequest) Descending() bool {
	return s.SortOrder == SortDescending
}

// Limits are the pagination bounds of one provider. Table 6 of Section 3.4.2.4
// leaves the maximum to the provider, so it is configuration rather than a
// constant of the protocol.
type Limits struct {
	DefaultCount int
	MaxCount     int
}

// DefaultLimits are the bounds a provider gets until it states its own.
var DefaultLimits = Limits{DefaultCount: 100, MaxCount: 100}

// ParseSearchRequest reads the query parameters of Section 3.4.2 into the
// request they describe, holding the client to this provider's Limits.
//
// SortBy and Filter are carried through untouched. Both name attributes, and
// only the schema of the resource being queried says which attributes exist,
// so it is the server that resolves them and reports an attribute it does not
// know. An error is a *Error, ready to answer the request.
func (l Limits) ParseSearchRequest(values url.Values) (*SearchRequest, error) {
	startIndex, err := intParam(values, "startIndex", 1)
	if err != nil {
		return nil, err
	}

	count, err := intParam(values, "count", l.DefaultCount)
	if err != nil {
		return nil, err
	}

	sortOrder, err := sortOrderParam(values)
	if err != nil {
		return nil, err
	}

	return &SearchRequest{
		Schemas:            []core.SchemaURI{SchemaSearchRequest},
		Attributes:         listParam(values, "attributes"),
		ExcludedAttributes: listParam(values, "excludedAttributes"),
		Filter:             values.Get("filter"),
		SortBy:             values.Get("sortBy"),
		SortOrder:          sortOrder,
		StartIndex:         max(startIndex, 1),
		Count:              min(max(count, 0), l.MaxCount),
	}, nil
}

func sortOrderParam(values url.Values) (SortOrder, error) {
	switch order := SortOrder(values.Get("sortOrder")); order {
	case SortAscending, SortDescending:
		return order, nil
	case "":
		if values.Get("sortBy") != "" {
			return SortAscending, nil
		}
		return "", nil
	default:
		return "", ErrInvalidValue(`"sortOrder" must be "ascending" or "descending"`)
	}
}

func listParam(values url.Values, name string) []string {
	var list []string

	for _, value := range values[name] {
		for _, item := range strings.Split(value, ",") {
			if item = strings.TrimSpace(item); item != "" {
				list = append(list, item)
			}
		}
	}
	return list
}

func intParam(values url.Values, name string, fallback int) (int, error) {
	raw := values.Get(name)
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, ErrInvalidValue(strconv.Quote(name) + " must be an integer")
	}
	return value, nil
}
