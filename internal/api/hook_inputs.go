package api

// TODO: Find a way to exclude all structs in this file from checks
type CustomSMSSenderRequest struct {
	//lint:ignore U1000 This struct's fields are intentionally unused. They are used for generation of jsonschema which is stored in the database.
	phone string
}
