// Package e2ehooks provides utilities for end-to-end testing of hooks.
package e2ehooks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"slices"
	"sync"

	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/e2e/e2eapi"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/hooks/v1hooks"
)

type Instance struct {
	*e2eapi.Instance

	HookServer   *httptest.Server
	HookRecorder *HookRecorder
}

func (o *Instance) Close() error {
	defer o.Instance.Close()
	defer o.HookServer.Close()
	return nil
}

func New(globalCfg *conf.GlobalConfiguration) (*Instance, error) {
	hookRec := NewHookRecorder()
	hookSrv := httptest.NewServer(hookRec)
	hookRec.Register(&globalCfg.Hook, hookSrv.URL)

	test, err := e2eapi.New(globalCfg)
	if err != nil {
		defer hookSrv.Close()

		return nil, err
	}

	o := &Instance{
		Instance:     test,
		HookServer:   hookSrv,
		HookRecorder: hookRec,
	}
	return o, nil
}

type Hook struct {
	mu    sync.Mutex
	name  v0hooks.Name
	calls []*HookCall

	res string
	hdr http.Header
}

func NewHook(name v0hooks.Name) *Hook {
	o := &Hook{
		name: name,
	}
	o.SetResponse(`{}`, http.Header{
		"content-type": []string{"application/json"},
	})
	return o
}

func (o *Hook) GetCalls() []*HookCall {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.calls)
}

func (o *Hook) SetResponse(res string, hdr http.Header) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.res = res
	o.hdr = hdr
}

func (o *Hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()

	dump, _ := httputil.DumpRequest(r, true)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		code := http.StatusInternalServerError
		http.Error(w, http.StatusText(code), code)
		return
	}

	hc := &HookCall{
		Dump:   string(dump),
		Body:   string(body),
		Header: r.Header.Clone(),
	}
	o.calls = append(o.calls, hc)

	for name, vals := range o.hdr {
		for _, val := range vals {
			w.Header().Add(name, val)
		}
	}
	_, _ = io.WriteString(w, o.res)
}

type HookCall struct {
	Header http.Header
	Body   string
	Dump   string
}

func (o *HookCall) Unmarshal(v any) error {
	return json.Unmarshal([]byte(o.Body), v)
}

type HookRecorder struct {
	mux               *http.ServeMux
	BeforeUserCreated *Hook
	AfterUserCreated  *Hook
}

func NewHookRecorder() *HookRecorder {
	o := &HookRecorder{
		mux:               http.NewServeMux(),
		BeforeUserCreated: NewHook(v1hooks.BeforeUserCreated),
		AfterUserCreated:  NewHook(v1hooks.AfterUserCreated),
	}

	o.mux.HandleFunc("POST /hooks/{hook}", func(w http.ResponseWriter, r *http.Request) {
		//exhaustive:ignore
		switch v0hooks.Name(r.PathValue("hook")) {
		case v1hooks.BeforeUserCreated:
			o.BeforeUserCreated.ServeHTTP(w, r)

		case v1hooks.AfterUserCreated:
			o.AfterUserCreated.ServeHTTP(w, r)

		default:
			http.NotFound(w, r)
		}
	})
	return o
}

func (o *HookRecorder) Register(
	hookCfg *conf.HookConfiguration,
	baseURL string,
) {
	hookCfg.BeforeUserCreated = conf.ExtensibilityPointConfiguration{
		Enabled: true,
		URI:     baseURL + "/hooks/" + string(v1hooks.BeforeUserCreated),
	}
	hookCfg.AfterUserCreated = conf.ExtensibilityPointConfiguration{
		Enabled: true,
		URI:     baseURL + "/hooks/" + string(v1hooks.AfterUserCreated),
	}
}

func (o *HookRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mux.ServeHTTP(w, r)
}
