// Package e2eapi provides utilities for end-to-end testing the api.
package e2eapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
	"github.com/supabase/auth/internal/utilities"
)

type Instance struct {
	Config    *conf.GlobalConfiguration
	Conn      *storage.Connection
	APIServer *httptest.Server

	closers []func()
}

func New(globalCfg *conf.GlobalConfiguration) (*Instance, error) {
	o := new(Instance)
	o.Config = globalCfg

	conn, err := test.SetupDBConnection(globalCfg)
	if err != nil {
		return nil, fmt.Errorf("error setting up db connection: %w", err)
	}
	o.addCloser(func() {
		if conn.Store != nil {
			_ = conn.Close()
		}
	})
	o.Conn = conn

	apiVer := utilities.Version
	if apiVer == "" {
		apiVer = "1"
	}

	a := api.NewAPIWithVersion(globalCfg, conn, apiVer)
	apiSrv := httptest.NewServer(a)
	o.addCloser(apiSrv)
	o.APIServer = apiSrv

	return o, nil
}

func (o *Instance) Close() error {
	for _, fn := range o.closers {
		defer fn()
	}
	return nil
}

func (o *Instance) addCloser(v any) {
	switch T := any(v).(type) {
	case func():
		o.closers = append(o.closers, T)
	case interface{ Close() }:
		o.closers = append(o.closers, func() { T.Close() })
	}
}

func Do(
	ctx context.Context,
	method string,
	url string,
	req, res any,
) error {
	var rdr io.Reader
	if req != nil {
		buf := new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(req)
		if err != nil {
			return err
		}
		rdr = buf
	}

	data, err := do(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, res); err != nil {
		return err
	}
	return nil
}

func do(
	ctx context.Context,
	method string,
	url string,
	body io.Reader,
) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	h := httpReq.Header
	h.Add("X-Client-Info", "auth-go/v1.0.0")
	h.Add("X-Supabase-Api-Version", "2024-01-01")
	h.Add("Content-Type", "application/json")
	h.Add("Accept", "application/json")

	httpRes, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpRes.Body.Close()

	switch sc := httpRes.StatusCode; {
	case sc == http.StatusNoContent:
		return nil, nil

	case sc >= 400:
		data, err := io.ReadAll(io.LimitReader(httpRes.Body, 1e8))
		if err != nil {
			return nil, err
		}

		apiErr := new(api.HTTPErrorResponse20240101)
		if err := json.Unmarshal(data, apiErr); err != nil {
			return nil, err
		}

		err = &apierrors.HTTPError{
			HTTPStatus: sc,
			ErrorCode:  apiErr.Code,
			Message:    apiErr.Message,
		}
		return nil, err

	default:
		data, err := io.ReadAll(io.LimitReader(httpRes.Body, 1e8))
		if err != nil {
			return nil, err
		}
		return data, nil
	}
}
