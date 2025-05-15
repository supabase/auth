package hookserrors

import (
	"errors"
	"testing"

	"github.com/supabase/auth/internal/api/apierrors"
)

func TestFromBytes(t *testing.T) {
	cases := []struct {
		from string
		ok   bool
		exp  *Error
	}{
		{from: `<b>text</b>`},
		{from: `null`},
		{from: `{}`},
		{from: `{"key": "val"}`},
		{from: `{"error": null}`},

		{
			from: `{"error": {"message": "failed"}}`,
			ok:   true, exp: &Error{HTTPCode: 0, Message: "failed"},
		},
		{
			from: `{"error": {"http_code": 400}}`,
			ok:   true, exp: &Error{HTTPCode: 400},
		},
		{
			from: `{"error": {"message": "failed", "http_code": 400}}`,
			ok:   true, exp: &Error{HTTPCode: 400, Message: "failed"},
		},
		{
			from: `{"error": {"message": "failed", "http_code": 403}}`,
			ok:   true, exp: &Error{HTTPCode: 403, Message: "failed"},
		},
	}
	for idx, tc := range cases {
		t.Logf("test #%v - exp Check(%v) = (%#v, %v)", idx, tc.from, tc.exp, tc.ok)

		e, ok := fromBytes([]byte(tc.from))
		if exp, got := tc.ok, ok; exp != got {
			t.Fatalf("exp %v; got %v", exp, got)
		}
		if !tc.ok {
			if e != nil {
				t.Fatalf("exp nil; got %v", e)
			}
			continue
		}
		if exp, got := tc.exp.HTTPCode, e.HTTPCode; exp != got {
			t.Fatalf("exp HTTPCode %v; got %v", exp, got)
		}
		if exp, got := tc.exp.Message, e.Message; exp != got {
			t.Fatalf("exp Message %q; got %q", exp, got)
		}

		err := (error)(e)
		if exp, got := tc.exp.Message, err.Error(); exp != got {
			t.Fatalf("exp Error() %q; got %q", exp, got)
		}
	}
}

func TestCheck(t *testing.T) {
	{
		if err := Check([]byte(`invalidjson`)); err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		if err := Check([]byte(`{"error": nil}`)); err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		if err := Check([]byte(`{"error": {"message": "failed"}}`)); err == nil {
			t.Fatal("exp non-nil err")
		}

		{
			data := `{"error": {"message": "failed", "http_code": 403}}`
			err := Check([]byte(data))
			if err == nil {
				t.Fatal("exp non-nil err")
			}

			e, ok := err.(*apierrors.HTTPError)
			if !ok {
				t.Fatal("exp error to be http.Error")
			}
			if exp, got := e.HTTPStatus, 403; exp != got {
				t.Fatalf("exp HTTPCode %v; got %v", exp, got)
			}
			if exp, got := e.Message, "failed"; exp != got {
				t.Fatalf("exp Message %q; got %q", exp, got)
			}
		}
	}

	{
		if err := check(nil); err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		if err := check(&Error{Message: ""}); err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		if err := check(&Error{Message: "failed"}); err == nil {
			t.Fatal("exp non-nil err")
		}
	}
}

func TestAs(t *testing.T) {

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := new(apierrors.HTTPError)
		if !errors.As(err, &e) {
			t.Fatal("exp errors.As to return true")
		}
		if exp, got := e.HTTPStatus, 403; exp != got {
			t.Fatalf("exp HTTPCode %v; got %v", exp, got)
		}
		if exp, got := e.Message, "failed"; exp != got {
			t.Fatalf("exp Message %q; got %q", exp, got)
		}
	}

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := new(Error)
		if !errors.As(err, &e) {
			t.Fatal("exp errors.As to return true")
		}
		if exp, got := e.HTTPCode, 403; exp != got {
			t.Fatalf("exp HTTPCode %v; got %v", exp, got)
		}
		if exp, got := e.Message, "failed"; exp != got {
			t.Fatalf("exp Message %q; got %q", exp, got)
		}
	}

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := new(apierrors.HTTPError)
		if !err.As(&e) {
			t.Fatal("exp errors.As to return true")
		}
		if exp, got := e.HTTPStatus, 403; exp != got {
			t.Fatalf("exp HTTPCode %v; got %v", exp, got)
		}
		if exp, got := e.Message, "failed"; exp != got {
			t.Fatalf("exp Message %q; got %q", exp, got)
		}
	}

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := new(Error)
		if !err.As(&e) {
			t.Fatal("exp errors.As to return true")
		}
		if exp, got := e.HTTPCode, 403; exp != got {
			t.Fatalf("exp HTTPCode %v; got %v", exp, got)
		}
		if exp, got := e.Message, "failed"; exp != got {
			t.Fatalf("exp Message %q; got %q", exp, got)
		}
	}

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := new(apierrors.HTTPError)
		if !err.As(e) {
			t.Fatal("exp errors.As to return true")
		}
		if exp, got := e.HTTPStatus, 403; exp != got {
			t.Fatalf("exp HTTPCode %v; got %v", exp, got)
		}
		if exp, got := e.Message, "failed"; exp != got {
			t.Fatalf("exp Message %q; got %q", exp, got)
		}
	}

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := new(Error)
		if !err.As(e) {
			t.Fatal("exp errors.As to return true")
		}
		if exp, got := e.HTTPCode, 403; exp != got {
			t.Fatalf("exp HTTPCode %v; got %v", exp, got)
		}
		if exp, got := e.Message, "failed"; exp != got {
			t.Fatalf("exp Message %q; got %q", exp, got)
		}
	}

	{
		err := errors.New("sentinel")
		e := new(Error)
		if errors.As(err, &e) {
			t.Fatal("exp errors.As to return false")
		}
	}

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := (*Error)(nil)
		if err.As(&e) {
			t.Fatal("exp errors.As to return false")
		}
	}

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := (*apierrors.HTTPError)(nil)
		if err.As(&e) {
			t.Fatal("exp errors.As to return false")
		}
	}

	{
		err := &Error{
			Message:  "failed",
			HTTPCode: 403,
		}
		e := (*error)(nil)
		if err.As(&e) {
			t.Fatal("exp errors.As to return false")
		}
	}
}
