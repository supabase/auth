package query

import "github.com/supabase-community/scim-go/pkg/core"

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

func (r Reference) container(document core.Object) core.Object {
	if r.uri == "" {
		return document
	}
	extension, _ := document.Get(string(r.uri)).(map[string]any)
	return extension
}
