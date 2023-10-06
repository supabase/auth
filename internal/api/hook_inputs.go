package api

import "github.com/supabase/gotrue/internal/models"

// TODO: Find a way to exclude all structs in this file from checks
type CustomSMSSenderRequest struct {
	//lint:ignore U1000 This struct's fields are intentionally unused. They are used for generation of jsonschema which is stored in the database.
	phone string
}

func TransformCustomSMSExtensibilityPointInputs(user *models.User, metadata map[string]interface{}) (request interface{}, err error) {
	// Check if the user is not nil and has a phone number
	result := make(map[string]interface{})

	if user != nil && user.Phone != "" {
		// Add the phone number to the result map
		result["phone"] = string(user.Phone)
	}
	return result, nil

}
