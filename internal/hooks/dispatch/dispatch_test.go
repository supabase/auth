package dispatch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/hooks/hookerrors"
	"github.com/supabase/auth/internal/storage"
)

func TestDispatcher(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	basicErr := errors.New("error")
	basicErrSvc := &mockService{err: basicErr}
	hookErr := &hookerrors.Error{Message: "failed", HTTPCode: 403}
	hookErrSvc := &mockService{err: hookErr}

	cases := []struct {
		desc   string
		cfg    *conf.ExtensibilityPointConfiguration
		dr     *Dispatcher
		errStr string
	}{
		{
			desc: "success - dispatch to pg-functions",
			cfg: &conf.ExtensibilityPointConfiguration{
				URI: `pg-functions://postgres/test`,
			},
		},

		{
			desc: "success - dispatch to http uri",
			cfg: &conf.ExtensibilityPointConfiguration{
				URI: `http://localhost/test`,
			},
		},

		{
			desc: "success - dispatch to https uri",
			cfg: &conf.ExtensibilityPointConfiguration{
				URI: `https://localhost/test`,
			},
		},

		{
			desc: "failure - dispatch to invalid uri",
			cfg: &conf.ExtensibilityPointConfiguration{
				URI: `unknown://localhost/test`,
			},
			errStr: `unsupported protocol: "unknown://localhost/test"`,
		},

		{
			desc: "failure - dispatch has service error",
			cfg: &conf.ExtensibilityPointConfiguration{
				URI: `https://localhost/test`,
			},
			dr:     New(hookErrSvc, hookErrSvc),
			errStr: `403: failed`,
		},

		{
			desc: "failure - dispatch has service error not HTTPError",
			cfg: &conf.ExtensibilityPointConfiguration{
				URI: `https://localhost/test`,
			},
			dr:     New(basicErrSvc, basicErrSvc),
			errStr: `500: Error running hook URI: https://localhost/test`,
		},
	}

	for idx, tc := range cases {
		t.Logf("test #%v - %v", idx, tc.desc)

		dr := tc.dr
		if dr == nil {
			mockSvc := &mockService{}
			dr = New(mockSvc, mockSvc)
		}

		err := dr.Dispatch(ctx, tc.cfg, nil, nil, nil)
		if tc.errStr != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errStr)
			continue
		}
		require.NoError(t, err)
	}
}

type mockService struct{ err error }

func (o *mockService) PGFuncDispatch(
	ctx context.Context,
	cfg conf.ExtensibilityPointConfiguration,
	tx *storage.Connection,
	req any,
	res any,
) error {
	return o.err
}

func (o *mockService) RunPostgresHook(
	ctx context.Context,
	hookConfig conf.ExtensibilityPointConfiguration,
	tx *storage.Connection,
	input any,
) ([]byte, error) {
	return nil, o.err
}

func (o *mockService) HTTPDispatch(
	ctx context.Context,
	cfg conf.ExtensibilityPointConfiguration,
	req any,
	res any,
) error {
	return o.err
}

func (o *mockService) RunHTTPHook(
	ctx context.Context,
	hookConfig conf.ExtensibilityPointConfiguration,
	input any,
) ([]byte, error) {
	return nil, o.err
}
