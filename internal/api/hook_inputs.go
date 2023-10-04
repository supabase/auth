package api

import "github.com/supabase/gotrue/internal/models"

// TODO: Get staticcheck to ignore this
// type CustomSMSSenderRequest struct {
// 	phone string
// }

func TransformCustomSMSExtensibilityPointInputs(user *models.User, metadata map[string]interface{}) (request interface{}, err error) {
	// Check if the user is not nil and has a phone number
	result := make(map[string]interface{})

	if user != nil && user.Phone != "" {
		// Add the phone number to the result map
		result["phone"] = string(user.Phone)
	}
	return result, nil

}
