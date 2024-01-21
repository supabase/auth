package provider

import "testing"

func TestIsAzureIssuer(t *testing.T) {
	positiveExamples := []string{
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/",
		"https://login.microsoftonline.com/common/v2.0",
	}

	negativeExamples := []string{
		"http://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0?something=else",
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/extra",
	}

	for _, example := range positiveExamples {
		if !IsAzureIssuer(example) {
			t.Errorf("Example %q should be treated as a valid Azure issuer", example)
		}
	}

	for _, example := range negativeExamples {
		if IsAzureIssuer(example) {
			t.Errorf("Example %q should be treated as not a valid Azure issuer", example)
		}
	}
}
