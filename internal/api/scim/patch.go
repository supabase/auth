package scim

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/supabase/auth/internal/api/scim/core"
	"github.com/supabase/auth/internal/api/scim/protocol"
)

func applyUserPatch(current *core.User, patch *protocol.PatchOp) (*core.User, error) {
	doc, err := userToDoc(current)
	if err != nil {
		return nil, err
	}

	for _, op := range patch.Operations {
		if err := applyPatchOperation(doc, op); err != nil {
			return nil, err
		}
	}

	patched, err := docToUser(doc)
	if err != nil {
		return nil, err
	}
	if patched.UserName == "" {
		return nil, protocol.ErrInvalidValue(`"userName" is required`)
	}
	patched.ID = current.ID
	patched.Meta = current.Meta
	return patched, nil
}

func applyPatchOperation(doc map[string]json.RawMessage, op protocol.PatchOperation) error {
	path, hasPath, err := op.Target()
	if err != nil {
		return err
	}

	switch op.Kind() {
	case protocol.PatchRemove:
		removeDocKey(doc, path.Name, path.Sub)
		return nil

	case protocol.PatchAdd, protocol.PatchReplace:
		if !hasPath {
			return mergeAttributes(doc, op.Value)
		}
		return setDocKey(doc, path.Name, path.Sub, op.Value)

	default:
		return protocol.ErrInvalidValue("unsupported patch operation")
	}
}

func mergeAttributes(doc map[string]json.RawMessage, value json.RawMessage) error {
	var attrs map[string]json.RawMessage
	if err := json.Unmarshal(value, &attrs); err != nil {
		return protocol.ErrInvalidValue("a patch with no path expects a set of attributes to replace")
	}

	for name, raw := range attrs {
		if err := setDocKey(doc, name, "", raw); err != nil {
			return err
		}
	}
	return nil
}

func setDocKey(doc map[string]json.RawMessage, name, sub string, value json.RawMessage) error {
	if sub == "" {
		deleteFold(doc, name)
		doc[name] = value
		return nil
	}

	child, err := childObject(doc, name)
	if err != nil {
		return err
	}
	deleteFold(child, sub)
	child[sub] = value

	encoded, err := json.Marshal(child)
	if err != nil {
		return fmt.Errorf("scim: encoding patched %s: %w", name, err)
	}
	deleteFold(doc, name)
	doc[name] = encoded
	return nil
}

func removeDocKey(doc map[string]json.RawMessage, name, sub string) {
	if sub == "" {
		deleteFold(doc, name)
		return
	}

	child, err := childObject(doc, name)
	if err != nil {
		return
	}
	deleteFold(child, sub)

	if encoded, err := json.Marshal(child); err == nil {
		deleteFold(doc, name)
		doc[name] = encoded
	}
}

func childObject(doc map[string]json.RawMessage, name string) (map[string]json.RawMessage, error) {
	raw, ok := lookupFold(doc, name)
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return map[string]json.RawMessage{}, nil
	}

	var child map[string]json.RawMessage
	if err := json.Unmarshal(raw, &child); err != nil {
		return nil, protocol.ErrInvalidValue(strconv.Quote(name) + " is not a complex attribute")
	}
	return child, nil
}

func lookupFold(doc map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	for key, value := range doc {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func deleteFold(doc map[string]json.RawMessage, name string) {
	for key := range doc {
		if strings.EqualFold(key, name) {
			delete(doc, key)
		}
	}
}

func userToDoc(user *core.User) (map[string]json.RawMessage, error) {
	encoded, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("scim: encoding user to patch: %w", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &doc); err != nil {
		return nil, fmt.Errorf("scim: reading user to patch: %w", err)
	}
	return doc, nil
}

func docToUser(doc map[string]json.RawMessage) (*core.User, error) {
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("scim: encoding patched user: %w", err)
	}

	user := new(core.User)
	if err := json.Unmarshal(encoded, user); err != nil {
		return nil, protocol.ErrInvalidValue("the patched resource is not a valid User")
	}
	return user, nil
}
