package protocol

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/supabase/auth/internal/api/scim/core"
)

// PatchOpType is a PATCH operation, the "op" of RFC 7644, Section 3.5.2.
type PatchOpType string

const (
	PatchAdd     PatchOpType = "add"
	PatchRemove  PatchOpType = "remove"
	PatchReplace PatchOpType = "replace"
)

// PatchOp is the PATCH request body of RFC 7644, Section 3.5.2: an ordered list
// of operations applied to one resource.
type PatchOp struct {
	Schemas    []core.SchemaURI `json:"schemas,omitempty"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one operation of a PatchOp. Value is left raw so that its
// shape is the applying resource's to interpret: a whole set of attributes when
// the operation has no path, or one attribute's new value when it does.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Kind is the operation matched without regard to case, since "op" is a keyword
// of the protocol rather than data.
func (op PatchOperation) Kind() PatchOpType {
	return PatchOpType(strings.ToLower(op.Op))
}

// Target is the attribute an operation acts on. hasPath is false when the
// operation omits its path, which Section 3.5.2 defines as targeting the
// resource itself. A valuePath, or any path that is not a plain attribute, is
// ErrInvalidPath: this server modifies whole attributes, not selected values.
func (op PatchOperation) Target() (path AttrPath, hasPath bool, err error) {
	if op.Path == "" {
		return AttrPath{}, false, nil
	}
	if strings.ContainsAny(op.Path, "[]") {
		return AttrPath{}, false, ErrInvalidPath(strconv.Quote(op.Path) +
			" selects values, which this server does not patch")
	}
	path, err = parseAttrPathText(op.Path)
	if err != nil {
		return AttrPath{}, false, ErrInvalidPath(strconv.Quote(op.Path) + " is not a valid path")
	}
	return path, true, nil
}

// ParsePatchOp reads and validates a PATCH body. A body that is not the message
// of Section 3.5.2 -- malformed, empty of operations, or carrying an operation
// this server will not perform -- is one of the errors of Section 3.12, ready
// to answer the request.
func ParsePatchOp(body []byte) (*PatchOp, error) {
	var patch PatchOp
	if err := json.Unmarshal(body, &patch); err != nil {
		return nil, ErrInvalidSyntax("request body is not a valid PatchOp")
	}

	if len(patch.Operations) == 0 {
		return nil, ErrInvalidValue(`"Operations" must contain at least one operation`)
	}

	for _, op := range patch.Operations {
		if err := op.validate(); err != nil {
			return nil, err
		}
	}
	return &patch, nil
}

func (op PatchOperation) validate() error {
	switch op.Kind() {
	case PatchAdd, PatchReplace, PatchRemove:
	default:
		return ErrInvalidValue(strconv.Quote(op.Op) + ` is not "add", "remove", or "replace"`)
	}

	// "remove" names what to remove; without a path there is nothing to act on,
	// which Section 3.5.2 answers with "noTarget".
	if op.Kind() == PatchRemove && op.Path == "" {
		return ErrNoTarget(`"remove" requires a "path"`)
	}

	_, _, err := op.Target()
	return err
}
