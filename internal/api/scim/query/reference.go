package query

import (
	"strings"

	"github.com/supabase-community/scim-go/pkg/core"
	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/patch"
)

const (
	ValueAttribute       = "value"
	displayNameAttribute = "displayName"
	uuidPattern          = `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
)

type kind int

const (
	single kind = iota
	multi
	inverse
)

type Edge struct {
	Type      string
	Attribute string
}

type Reference struct {
	attribute *core.Attribute
	uri       core.SchemaURI
	kind      kind
	targets   []string
	via       Edge
	nested    bool
}

func (r Reference) Name() string {
	return r.attribute.Name
}

func (r Reference) Path() string {
	if r.uri == "" {
		return r.Name()
	}
	return string(r.uri) + ":" + r.Name()
}

func (r Reference) Targets() []string {
	if r.kind != multi {
		return nil
	}
	return r.targets
}

func (r Reference) Nested() bool {
	return r.nested
}

func (r Reference) Get(document core.Object) any {
	return r.container(document).Get(r.Name())
}

func (r Reference) Strip(document core.Object) {
	container := r.container(document)
	if r.kind != single {
		container.Remove(r.Name())
		return
	}
	value, _ := container.Get(r.Name()).(map[string]any)
	for _, sub := range r.attribute.SubAttributes {
		if sub.Name == "$ref" || sub.Mutability == core.MutabilityReadOnly {
			delete(value, sub.Name)
		}
	}
}

func (r Reference) resolves(sub string) bool {
	return r.kind != single || sub == r.shown()
}

func (r Reference) computed(sub string) bool {
	return r.kind != single || sub != ValueAttribute
}

func (r Reference) container(document core.Object) core.Object {
	if r.uri == "" {
		return document
	}
	extension, _ := document.Get(string(r.uri)).(map[string]any)
	return extension
}

func (r Reference) shown() string {
	for _, name := range []string{"display", displayNameAttribute} {
		if sub := r.attribute.SubAttribute(name); sub != nil {
			return sub.Name
		}
	}
	return ""
}

func (r Reference) display(table string) string {
	shown := r.shown()
	if shown == "" {
		return ""
	}
	return `, ` + QuoteLiteral(shown) + `, ` + table + `.resource ->> ` + QuoteLiteral(displayNameAttribute)
}

func (r Reference) keys() []string {
	keys := []string{r.Name(), ValueAttribute}
	if r.uri != "" {
		keys = append([]string{string(r.uri)}, keys...)
	}
	return keys
}

func (r Reference) values(op patch.Operation, path filter.Path) []string {
	if r.kind != multi || r.attribute.Required || path.SubAttribute != "" {
		return nil
	}
	switch patch.Op(strings.ToLower(string(op.Op))) {
	case patch.OpAdd:
		return added(op, path)
	case patch.OpRemove:
		return removed(path)
	}
	return nil
}

func resourceTypes(attribute *core.Attribute) []string {
	ref := attribute.SubAttribute("$ref")
	if attribute.Type != core.TypeComplex || ref == nil {
		return nil
	}
	types := []string{}
	for _, t := range ref.ReferenceTypes {
		if t != core.ReferenceExternal && t != core.ReferenceURI {
			types = append(types, string(t))
		}
	}
	return types
}
