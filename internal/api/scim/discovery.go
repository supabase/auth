package scim

import "github.com/supabase/auth/internal/api/scim/core"

func newUserSchema(baseURL string) *core.Schema {
	return core.
		NewSchema(baseURL, core.SchemaUser, core.ResourceTypeUser).
		Describe("User Account").
		With(
			core.NewAttribute("userName", core.TypeString,
				"Unique identifier for the User, typically used by the user to directly authenticate to the service provider.").
				AsRequired().
				UniqueOn(core.UniquenessServer),

			core.NewAttribute("name", core.TypeComplex,
				"The components of the user's real name.").
				With(
					core.NewAttribute("formatted", core.TypeString, "The full name, including all middle names, titles, and suffixes as appropriate, formatted for display."),
					core.NewAttribute("familyName", core.TypeString, "The family name of the User, or last name in most Western languages."),
					core.NewAttribute("givenName", core.TypeString, "The given name of the User, or first name in most Western languages."),
				),

			core.NewAttribute("emails", core.TypeComplex,
				"Email addresses for the User. Only the primary address is supported.").
				AsMultiValued().
				With(
					core.NewAttribute("value", core.TypeString, "Email address for the User."),
					core.NewAttribute("primary", core.TypeBoolean, "A Boolean value indicating the preferred email address."),
				),

			core.NewAttribute("active", core.TypeBoolean,
				"A Boolean value indicating the User's administrative status."),

			core.NewAttribute("externalId", core.TypeString,
				"An identifier for the User as defined by the provisioning client.").
				AsCaseExact(),
		)
}
