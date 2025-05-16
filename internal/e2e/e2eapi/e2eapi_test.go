package e2eapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/models"
)

func TestInstance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
	defer cancel()

	globalCfg := e2e.Must(e2e.Config())
	inst, err := New(globalCfg)
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	defer inst.Close()

	{
		email := "e2etesthooks_" + uuid.Must(uuid.NewV4()).String() + "@localhost"
		req := &api.SignupParams{
			Email:    email,
			Password: "password",
		}
		res := new(models.User)
		err := Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, res)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
		require.Equal(t, email, res.Email.String())
	}
}

func TestNew(t *testing.T) {
	{
		globalCfg := e2e.Must(e2e.Config())
		globalCfg.DB.Driver = ""
		globalCfg.DB.URL = "invalid"

		inst, err := New(globalCfg)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
		if inst != nil {
			t.Fatal("exp nil *Instance")
		}
	}
}

func TestDo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	globalCfg := e2e.Must(e2e.Config())
	inst, err := New(globalCfg)
	if err != nil {
		t.Fatalf("exp nil err; got %v", err)
	}
	defer inst.Close()

	{
		req := make(chan string)
		err := Do(ctx, http.MethodPost, "http://localhost", &req, nil)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
		require.ErrorContains(t, err, "json: unsupported type: chan string")
	}

	{
		res := make(chan string)
		err := Do(ctx, http.MethodGet, inst.APIServer.URL+"/user", nil, &res)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
		require.ErrorContains(t, err, "401: This endpoint requires a Bearer token")
	}

	{
		res := make(chan string)
		err := Do(ctx, http.MethodGet, inst.APIServer.URL+"/settings", nil, &res)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
		require.ErrorContains(t, err, "json: cannot unmarshal object into Go value of type chan string")
	}

	{
		err := Do(ctx, "\x01", "http://localhost", nil, nil)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
		require.ErrorContains(t, err, "net/http: invalid method")
	}

	{
		err := Do(ctx, http.MethodGet, inst.APIServer.URL+"/404", nil, nil)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
		require.ErrorContains(t, err, "invalid character")
	}

	{
		err := Do(ctx, http.MethodPost, "invalid", nil, nil)
		if err == nil {
			t.Fatal("exp non-nil err")
		}
		require.ErrorContains(t, err, "unsupported protocol")
	}

	func() {
		hr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		ts := httptest.NewServer(hr)
		defer ts.Close()

		err := Do(ctx, http.MethodPost, ts.URL, nil, nil)
		if err != nil {
			t.Fatalf("exp nil err; got %v", err)
		}
	}()

	for _, statusCode := range []int{http.StatusBadRequest, http.StatusOK} {
		func() {
			sentinel := errors.New("sentinel")
			rtFn := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					return nil, err
				}
				res.Body = io.NopCloser(iotest.ErrReader(sentinel))
				return res, nil
			})

			prev := defaultClient
			defer func() {
				defaultClient = prev
			}()
			defaultClient = new(http.Client)
			defaultClient.Transport = rtFn

			hr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
			})

			ts := httptest.NewServer(hr)
			defer ts.Close()

			err := Do(ctx, http.MethodPost, ts.URL, nil, nil)
			require.Error(t, err)
			require.Equal(t, sentinel, err)
		}()
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
