package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/observability"
)

func TestHandleResponseErrorWithHTTPError(t *testing.T) {
	examples := []struct {
		HTTPError    *HTTPError
		APIVersion   string
		ExpectedBody string
	}{
		{
			HTTPError:    apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Unable to parse JSON"),
			APIVersion:   "",
			ExpectedBody: "{\"code\":400,\"error_code\":\"" + apierrors.ErrorCodeBadJSON + "\",\"msg\":\"Unable to parse JSON\"}",
		},
		{
			HTTPError:    apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Unable to parse JSON"),
			APIVersion:   "2023-12-31",
			ExpectedBody: "{\"code\":400,\"error_code\":\"" + apierrors.ErrorCodeBadJSON + "\",\"msg\":\"Unable to parse JSON\"}",
		},
		{
			HTTPError:    apierrors.NewBadRequestError(apierrors.ErrorCodeBadJSON, "Unable to parse JSON"),
			APIVersion:   "2024-01-01",
			ExpectedBody: "{\"code\":\"" + apierrors.ErrorCodeBadJSON + "\",\"message\":\"Unable to parse JSON\"}",
		},
		{
			HTTPError: &HTTPError{
				HTTPStatus: http.StatusBadRequest,
				Message:    "Uncoded failure",
			},
			APIVersion:   "2024-01-01",
			ExpectedBody: "{\"code\":\"" + apierrors.ErrorCodeUnknown + "\",\"message\":\"Uncoded failure\"}",
		},
		{
			HTTPError: &HTTPError{
				HTTPStatus: http.StatusInternalServerError,
				Message:    "Unexpected failure",
			},
			APIVersion:   "2024-01-01",
			ExpectedBody: "{\"code\":\"" + apierrors.ErrorCodeUnexpectedFailure + "\",\"message\":\"Unexpected failure\"}",
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

func TestRecoverer(t *testing.T) {
	var logBuffer bytes.Buffer
	config, err := conf.LoadGlobal(apiTestConfig)
	require.NoError(t, err)
	require.NoError(t, observability.ConfigureLogging(&config.Logging))

	// logrus should write to the buffer so we can check if the logs are output correctly
	logrus.SetOutput(&logBuffer)
	panicHandler := recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	w := httptest.NewRecorder()
	req, err := http.NewRequest(http.MethodPost, "http://example.com", nil)
	require.NoError(t, err)

	panicHandler.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)

	var data HTTPError

	// panic should return an internal server error
	require.NoError(t, json.NewDecoder(w.Body).Decode(&data))
	require.Equal(t, apierrors.ErrorCodeUnexpectedFailure, data.ErrorCode)
	require.Equal(t, http.StatusInternalServerError, data.HTTPStatus)
	require.Equal(t, "Internal Server Error", data.Message)

	// panic should log the error message internally
	var logs map[string]interface{}
	require.NoError(t, json.NewDecoder(&logBuffer).Decode(&logs))
	require.Equal(t, "request panicked", logs["msg"])
	require.Equal(t, "test panic", logs["panic"])
	require.NotEmpty(t, logs["stack"])
}
