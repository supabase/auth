package hooks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

const (
	apiTestVersion = "1"
	apiTestConfig  = "../../hack/test.env"
)

func TestNewManager(t *testing.T) {
	{
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
		defer cancel()

		config := helpConfig(t, apiTestConfig)
		conn := helpConn(t, config)

		hr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("content-type", "application/json")

			fmt.Fprintln(w, `{}`)
		})

		ts := httptest.NewServer(hr)
		defer ts.Close()

		config.Hook.SendEmail.Enabled = true
		config.Hook.SendEmail.URI = ts.URL + "/SendEmail"

		a := newAPI(config, conn)
		mgr := hooks.NewManager(a.GetDB(), a.GetConfig())

		{
			in := &v0hooks.SendEmailInput{
				User: &models.User{
					ID: uuid.Must(uuid.NewV4()),
				},
			}
			buf := new(bytes.Buffer)
			err := json.NewEncoder(buf).Encode(in)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}

			out := &v0hooks.SendEmailOutput{}
			req, err := http.NewRequestWithContext(
				ctx, "POST", config.Hook.SendEmail.URI, buf)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}

			err = mgr.InvokeHook(nil, req, in, out)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}
			if exp, got := "", out.HookError.Message; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
		}

		{
			in := &v0hooks.SendEmailInput{
				User: &models.User{
					ID: uuid.Must(uuid.NewV4()),
				},
			}
			buf := new(bytes.Buffer)
			err := json.NewEncoder(buf).Encode(in)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}

			req, err := http.NewRequestWithContext(
				ctx, "POST", config.Hook.SendEmail.URI, buf)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}

			res, err := mgr.RunHTTPHook(req, config.Hook.SendEmail, in)
			if err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}

			out := &v0hooks.SendEmailOutput{}
			if err := json.Unmarshal(res, out); err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}
			if exp, got := "", out.HookError.Message; exp != got {
				t.Fatalf("exp %v; got %v", exp, got)
			}
		}
	}
}

func newAPI(
	config *conf.GlobalConfiguration,
	conn *storage.Connection,
) *api.API {
	limiterOpts := api.NewLimiterOptions(config)
	return api.NewAPIWithVersion(config, conn, apiTestVersion, limiterOpts)
}

func helpConfig(tb testing.TB, configPath string) *conf.GlobalConfiguration {
	tb.Helper()

	config, err := conf.LoadGlobal(configPath)
	if err != nil {
		tb.Fatalf("error loading config %q; got %v", configPath, err)
	}
	return config
}

func helpConn(tb testing.TB, config *conf.GlobalConfiguration) *storage.Connection {
	tb.Helper()

	conn, err := test.SetupDBConnection(config)
	if err != nil {
		tb.Fatalf("error setting up db connection: %v", err)
	}
	return conn
}
