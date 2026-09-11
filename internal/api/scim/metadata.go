package scim

import (
	"github.com/supabase-community/scim-go/pkg/core"
)

const userResourceType = "User"

func newServiceProviderConfig(baseURL string, schemes ...*core.AuthenticationScheme) *core.ServiceProviderConfig {
	if schemes == nil {
		schemes = []*core.AuthenticationScheme{}
	}
	return &core.ServiceProviderConfig{
		Schemas:               []core.SchemaURI{core.SchemaServiceProviderConfig},
		AuthenticationSchemes: schemes,
		Meta: core.Meta{
			ResourceType: "ServiceProviderConfig",
			Location:     Join(baseURL, "/ServiceProviderConfig"),
		},
	}
}

func newUserResourceType(baseURL string, schema *core.Schema) *core.ResourceType {
	return &core.ResourceType{
		Schemas:     []core.SchemaURI{core.SchemaResourceType},
		ID:          userResourceType,
		Name:        userResourceType,
		Description: schema.Description,
		Endpoint:    "/Users",
		Schema:      schema.ID,
		Meta: core.Meta{
			ResourceType: "ResourceType",
			Location:     Join(Join(baseURL, "/ResourceTypes"), userResourceType),
		},
	}
}

func newUserSchema(baseURL string) *core.Schema {
	return userSchemaHeader(baseURL).
		Describe("User Account").
		With(
			core.NewAttribute("userName", core.TypeString, "Unique identifier for the User").
				AsRequired().
				UniqueOn(core.UniquenessServer),
			nameAttribute(),
			core.NewAttribute("displayName", core.TypeString, "The name of the User, suitable for display."),
			emailsAttribute(),
			core.NewAttribute("active", core.TypeBoolean, ""),
		)
}

func userSchemaHeader(baseURL string) *core.Schema {
	return &core.Schema{
		Schemas: []core.SchemaURI{core.SchemaSchema},
		ID:      core.SchemaUser,
		Name:    userResourceType,
		Meta: core.Meta{
			ResourceType: "Schema",
			Location:     Join(Join(baseURL, "/Schemas"), string(core.SchemaUser)),
		},
	}
}

func nameAttribute() *core.Attribute {
	return core.NewAttribute("name", core.TypeComplex, "The components of the user's name.").
		With(
			core.NewAttribute("formatted", core.TypeString, "The name formatted for display."),
			core.NewAttribute("familyName", core.TypeString, "The family name of the User."),
			core.NewAttribute("givenName", core.TypeString, "The given name of the User."),
			core.NewAttribute("middleName", core.TypeString, "The middle name(s) of the User."),
		)
}

func emailsAttribute() *core.Attribute {
	return core.NewAttribute("emails", core.TypeComplex, "Email addresses for the user.").
		AsMultiValued().
		With(
			core.NewAttribute("value", core.TypeString, "An email address for the user."),
			core.NewAttribute("type", core.TypeString, "The type of email address."),
			core.NewAttribute("primary", core.TypeBoolean, "The 'primary' email address"),
		)
}
