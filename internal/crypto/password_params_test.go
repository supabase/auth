package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNonDefaultHashParameters(t *testing.T) {
	params, ok := NonDefaultHashParameters("$2y$10$va66S4MxFrH6G6L7BzYl0.QgcYgvSr/F92gc.3botlz7bG4p/g/1i")
	require.False(t, ok)
	require.Nil(t, params)

	params, ok = NonDefaultHashParameters("$2y$11$4lH57PU7bGATpRcx93vIoObH3qDmft/pytbOzDG9/1WsyNmN5u4di")
	require.True(t, ok)
	require.Equal(t, map[string]any{"alg": "bcrypt", "cost": 11}, params)

	params, ok = NonDefaultHashParameters("$argon2id$v=19$m=32,t=3,p=2$SFVpOWJ0eXhjRzVkdGN1RQ$RXnb8rh7LaDcn07xsssqqulZYXOM/EUCEFMVcAcyYVk")
	require.True(t, ok)
	require.Equal(t, "argon2id", params["alg"])
	require.EqualValues(t, 32, params["m"])
	require.EqualValues(t, 3, params["t"])
	require.EqualValues(t, 2, params["p"])
	require.NotContains(t, params, "salt")

	params, ok = NonDefaultHashParameters("$fbscrypt$v=1,n=14,r=8,p=1,ss=Bw==,sk=ou9tdYTGyYm8kuR6Dt0Bp0kDuAYoXrK16mbZO4yGwAn3oLspjnN0/c41v8xZnO1n14J3MjKj1b2g6AUCAlFwMw==$C0sHCg9ek77hsg==$zKVTMvnWVw5BBOZNUdnsalx4c4c7y/w7IS5p6Ut2+CfEFFlz37J9huyQfov4iizN8dbjvEJlM5tQaJP84+hfTw==")
	require.True(t, ok)
	require.Equal(t, "fbscrypt", params["alg"])
	require.EqualValues(t, 14, params["n_log2"])
	require.EqualValues(t, 8, params["r"])
	require.EqualValues(t, 1, params["p"])
	require.NotContains(t, params, "sk")
	require.NotContains(t, params, "ss")

	params, ok = NonDefaultHashParameters("garbage")
	require.True(t, ok)
	require.Equal(t, true, params["parse_error"])
}
