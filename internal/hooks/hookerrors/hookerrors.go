package hookerrors

import (
	"encoding/json"
	"net/http"

	"github.com/supabase/auth/internal/api/apierrors"
)

type Error struct {
	HTTPCode int    `json:"http_code,omitempty"`
	Message  string `json:"message,omitempty"`
}

func (e *Error) Error() string { return e.Message }
func (e *Error) As(target any) bool {
	switch T := target.(type) {
	case **Error:
		v := (*T)
		if v == nil {
			return false
		}
		v.HTTPCode = e.HTTPCode
		v.Message = e.Message
		return true
	case *Error:
		T.HTTPCode = e.HTTPCode
		T.Message = e.Message
		return true
	case **apierrors.HTTPError:
		v := (*T)
		if v == nil {
			return false
		}
		v.HTTPStatus = e.HTTPCode
		v.Message = e.Message
		return true
	case *apierrors.HTTPError:
		T.HTTPStatus = e.HTTPCode
		T.Message = e.Message
		return true
	default:
		return false
	}
}

func Check(b []byte) error {
	e, ok := fromBytes(b)
	if !ok {
		return nil
	}
	return check(e)
}

func check(e *Error) error {
	if e == nil {
		return nil
	}

	// TODO(cstockton): Changing this would be a BC break, but it also
	// doesn't seem to be the best API. For example returning an error object
	// with an http_code field set to 500 would not count as an error.
	if e.Message == "" {
		return nil
	}

	httpCode := e.HTTPCode
	if httpCode == 0 {
		httpCode = http.StatusInternalServerError
	}

	httpError := &apierrors.HTTPError{
		HTTPStatus: httpCode,
		Message:    e.Message,
	}
	return httpError.WithInternalError(e)
}

func fromBytes(b []byte) (*Error, bool) {
	var dst struct {
		Error *struct {
			HTTPCode int    `json:"http_code,omitempty"`
			Message  string `json:"message,omitempty"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(b, &dst); err != nil {
		return nil, false
	}
	if dst.Error == nil {
		return nil, false
	}
	e := &Error{
		HTTPCode: dst.Error.HTTPCode,
		Message:  dst.Error.Message,
	}
	return e, true
}
