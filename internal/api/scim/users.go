package scim

import "github.com/supabase-community/scim-go/pkg/core"

func userAttributes() core.Attributes {
	return core.Attributes{
		core.NewAttribute("userName", core.TypeString).AsRequired().UniqueOn(core.UniquenessServer),
		core.NewAttribute("name", core.TypeComplex).With(
			core.NewAttribute("givenName", core.TypeString),
			core.NewAttribute("familyName", core.TypeString),
		),
		core.NewAttribute("active", core.TypeBoolean),
		core.NewMultiValuedAttribute("emails", "work", "home", "other"),
	}
}
