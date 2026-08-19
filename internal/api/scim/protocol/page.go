package protocol

import (
	"fmt"
	"net/url"
	"strconv"
)

const (
	// DefaultCount is the page size used when a client asks for no particular
	// one. RFC 7644, Section 3.4.2.4 leaves that maximum to the provider.
	DefaultCount = 100

	// MaxCount is the largest page this provider will return. Asking for more
	// is allowed; the RFC only forbids returning more than was asked for.
	MaxCount = 100
)

// Page is the window of a collection a client asked for, per RFC 7644,
// Section 3.4.2.4. StartIndex counts resources from 1, not pages.
type Page struct {
	StartIndex int
	Count      int
}

func ParsePage(values url.Values) (Page, error) {
	startIndex, err := intParam(values, "startIndex", 1)
	if err != nil {
		return Page{}, err
	}

	count, err := intParam(values, "count", DefaultCount)
	if err != nil {
		return Page{}, err
	}

	return Page{
		StartIndex: max(startIndex, 1),
		Count:      min(max(count, 0), MaxCount),
	}, nil
}

func (p Page) Offset() int {
	return p.StartIndex - 1
}

func intParam(values url.Values, name string, fallback int) (int, error) {
	raw := values.Get(name)
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%q must be an integer", name)
	}
	return value, nil
}
