package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandleResponseErrorWithHTTPError(t *testing.T) {
	examples := []struct {
		HTTPError    *HTTPError
		APIVersion   string
		ExpectedBody string
	}{
		{
			HTTPError:    badRequestError(ErrorCodeBadJSON, "Unable to parse JSON"),
			APIVersion:   "",
			ExpectedBody: "{\"code\":400,\"error_code\":\"" + ErrorCodeBadJSON + "\",\"msg\":\"Unable to parse JSON\"}",
		},
		{
			HTTPError:    badRequestError(ErrorCodeBadJSON, "Unable to parse JSON"),
			APIVersion:   "2023-12-31",
			ExpectedBody: "{\"code\":400,\"error_code\":\"" + ErrorCodeBadJSON + "\",\"msg\":\"Unable to parse JSON\"}",
		},
		{
			HTTPError:    badRequestError(ErrorCodeBadJSON, "Unable to parse JSON"),
			APIVersion:   "2024-01-01",
			ExpectedBody: "{\"code\":\"" + ErrorCodeBadJSON + "\",\"message\":\"Unable to parse JSON\"}",
		},
		{
			HTTPError: &HTTPError{
				HTTPStatus: http.StatusBadRequest,
				Message:    "Uncoded failure",
			},
			APIVersion:   "2024-01-01",
			ExpectedBody: "{\"code\":\"" + ErrorCodeUnknown + "\",\"message\":\"Uncoded failure\"}",
		},
		{
			HTTPError: &HTTPError{
				HTTPStatus: http.StatusInternalServerError,
				Message:    "Unexpected failure",
			},
			APIVersion:   "2024-01-01",
			ExpectedBody: "{\"code\":\"" + ErrorCodeUnexpectedFailure + "\",\"message\":\"Unexpected failure\"}",
		},
	}

	for _, example := range examples {
		rec := httptest.NewRecorder()
		req, err := http.NewRequest(http.MethodPost, "http://example.com", nil)
		require.NoError(t, err)

		if example.APIVersion != "" {
			req.Header.Set(APIVersionHeaderName, example.APIVersion)
		}

		HandleResponseError(example.HTTPError, rec, req)

		require.Equal(t, example.HTTPError.HTTPStatus, rec.Code)
		require.Equal(t, example.ExpectedBody, rec.Body.String())
	}
}
