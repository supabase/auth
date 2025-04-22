package v0pgfunc

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type M = map[string]any

func TestDispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	globalCfg := helpConfig(t, apiTestConfig)
	db := helpConn(t, globalCfg)

	type testCase struct {
		ctx    context.Context
		desc   string
		tx     *storage.Connection
		dr     *Dispatcher
		cfg    conf.ExtensibilityPointConfiguration
		sql    string
		req    any
		exp    any
		err    error
		errStr string
	}

	cases := []testCase{

		{
			desc: "pass - returns json",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_return_input`,
				HookName: `"auth"."v0pgfunc_test_return_input"`,
			},
			req: M{"user": M{"ID": "16e3c032-a7ea-4388-b880-756c0d02202c"}},
			exp: M{"user": M{"ID": "16e3c032-a7ea-4388-b880-756c0d02202c"}},
			sql: `
				create or replace function v0pgfunc_test_return_input(input jsonb)
				returns json as $$
				begin
					return input;
				end; $$ language plpgsql;`,
		},

		{
			desc: "pass - returns json with conn for tx",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_return_input`,
				HookName: `"auth"."v0pgfunc_test_return_input"`,
			},
			tx:  db,
			req: M{"user": M{"ID": "16e3c032-a7ea-4388-b880-756c0d02202c"}},
			exp: M{"user": M{"ID": "16e3c032-a7ea-4388-b880-756c0d02202c"}},
			sql: `
				create or replace function v0pgfunc_test_return_input(input jsonb)
				returns json as $$
				begin
					return input;
				end; $$ language plpgsql;`,
		},

		{
			desc: "pass - small sleep of 50ms within timeout (100ms)",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_sleep_timeout`,
				HookName: `"auth"."v0pgfunc_test_sleep_timeout"`,
			},
			dr: New(
				db,
				WithTimeout(time.Millisecond*100),
			),
			req: M{"user": M{"ID": "16e3c032-a7ea-4388-b880-756c0d02202c"}},
			exp: M{"user": M{"ID": "16e3c032-a7ea-4388-b880-756c0d02202c"}},
			sql: `
				create or replace function v0pgfunc_test_sleep_timeout(input jsonb)
				returns json as $$
				begin
					PERFORM pg_sleep(0.05);
					return input;
				end; $$ language plpgsql;`,
		},

		{
			desc: "fail - small sleep of 50ms within timeout (40ms)",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_sleep_timeout`,
				HookName: `"auth"."v0pgfunc_test_sleep_timeout"`,
			},
			dr: New(
				db,
				WithTimeout(time.Millisecond*40),
			),
			req: M{"user": M{"ID": "16e3c032-a7ea-4388-b880-756c0d02202c"}},
			exp: M{"user": M{"ID": "16e3c032-a7ea-4388-b880-756c0d02202c"}},
			sql: `
				create or replace function v0pgfunc_test_sleep_timeout(input jsonb)
				returns json as $$
				begin
					PERFORM pg_sleep(0.05);
					return input;
				end; $$ language plpgsql;`,
			errStr: `ERROR: canceling statement due to statement timeout`,
		},

		{
			desc: "fail - func does not exist",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_NOT_EXIST`,
				HookName: `"auth"."v0pgfunc_test_NOT_EXIST"`,
			},
			req:    M{"user": M{"ID": uuid.Must(uuid.NewV4())}},
			errStr: "auth.v0pgfunc_test_NOT_EXIST(unknown) does not exist",
		},

		{
			desc: "fail - func does not exist with tx",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_NOT_EXIST`,
				HookName: `"auth"."v0pgfunc_test_NOT_EXIST"`,
			},
			tx:     db,
			req:    M{"user": M{"ID": uuid.Must(uuid.NewV4())}},
			errStr: "auth.v0pgfunc_test_NOT_EXIST(unknown) does not exist",
		},

		{
			desc: "fail - timeout is invalid",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_return_input`,
				HookName: `"auth"."v0pgfunc_test_return_input"`,
			},
			dr: New(
				db,
				WithTimeout(-time.Millisecond),
			),
			req:    M{"user": M{"ID": uuid.Must(uuid.NewV4())}},
			errStr: "ERROR: -1 ms is outside the valid range for parameter",
		},

		{
			desc: "fail - func is malformed",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_malformed`,
				HookName: `"auth". malform!#(%!*&!())`,
			},
			dr: New(
				db,
				WithTimeout(time.Millisecond*100),
			),
			req:    M{"user": M{"ID": uuid.Must(uuid.NewV4())}},
			errStr: "ERROR: syntax error at or near",
		},

		{
			desc:   "fail - unable to marshal",
			req:    make(chan int),
			errStr: "500: Error marshaling JSON input.",
		},

		{
			desc: "fail - unable to unmarshal",
			cfg: conf.ExtensibilityPointConfiguration{
				URI:      `pg-functions://postgres/auth/v0pgfunc_test_return_input`,
				HookName: `"auth"."v0pgfunc_test_return_input"`,
			},
			req: 12345,
			sql: `
				create or replace function v0pgfunc_test_return_input(input jsonb)
				returns json as $$
				begin
					return input;
				end; $$ language plpgsql;`,
			errStr: "500: Error unmarshaling JSON output.",
		},
	}

	for idx, tc := range cases {
		t.Logf("test #%v - %v", idx, tc.desc)

		testCtx := tc.ctx
		if testCtx == nil {
			testCtx = ctx
		}

		dr := tc.dr
		if dr == nil {
			dr = New(
				db,
				WithTimeout(time.Second*2),
			)
		}

		sql := tc.sql
		if sql != "" {
			if err := db.RawQuery(sql).Exec(); err != nil {
				t.Fatalf("exp nil err; got %v", err)
			}
		}

		tx := tc.tx
		cfg := tc.cfg
		res := M{}
		err := dr.Dispatch(testCtx, cfg, tx, tc.req, &res)
		if tc.err != nil {
			require.Error(t, err)
			require.Equal(t, tc.err, err)
			continue
		}
		if tc.errStr != "" {
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.errStr)
			continue
		}
		require.NoError(t, err)
		require.Equal(t, tc.exp, res)
	}
}

const (
	apiTestConfig = "../../../../hack/test.env"
)

func helpConfig(t testing.TB, configPath string) *conf.GlobalConfiguration {
	t.Helper()

	config, err := conf.LoadGlobal(configPath)
	if err != nil {
		t.Fatalf("error loading config %q; got %v", configPath, err)
	}
	return config
}

func helpConn(t testing.TB, config *conf.GlobalConfiguration) *storage.Connection {
	t.Helper()

	conn, err := test.SetupDBConnection(config)
	if err != nil {
		t.Fatalf("error setting up db connection: %v", err)
	}
	return conn
}
