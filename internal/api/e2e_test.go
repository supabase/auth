package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/dump"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/e2e/e2eapi"
	"github.com/supabase/auth/internal/e2e/e2ehooks"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/models"
)

func TestE2EHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	globalCfg := e2e.Must(e2e.Config())
	globalCfg.External.AnonymousUsers.Enabled = true

	inst, err := e2ehooks.New(globalCfg)
	require.NoError(t, err)
	defer inst.Close()

	apiSrv := inst.APIServer
	hookRec := inst.HookRecorder

	var currentUser *models.User

	runBeforeUserCreated := func(t *testing.T, expUser *models.User) {
		t.Run("BeforeUserCreated", func(t *testing.T) {
			calls := hookRec.BeforeUserCreated.GetCalls()
			require.Equal(t, 1, len(calls))
			call := calls[0]

			hookReq := &v0hooks.BeforeUserCreatedInput{}
			err := call.Unmarshal(hookReq)
			require.NoError(t, err)
			require.Equal(t, v0hooks.BeforeUserCreated, hookReq.Metadata.Name)

			u := hookReq.User
			require.Equal(t, expUser.ID, u.ID)
			require.Equal(t, expUser.Aud, u.Aud)
			require.Equal(t, expUser.Email, u.Email)
			require.Equal(t, expUser.AppMetaData, u.AppMetaData)

			require.True(t, u.CreatedAt.IsZero())
			require.True(t, u.UpdatedAt.IsZero())

			err = expUser.Confirm(inst.Conn)
			require.NoError(t, err)

			latest, err := models.FindUserByID(inst.Conn, expUser.ID)
			require.NoError(t, err)

			// Assign currentUser for next tests.
			currentUser = latest
			require.NotNil(t, currentUser)
		})
	}

	// Basic tests for user hooks
	t.Run("UserHooks", func(t *testing.T) {

		t.Run("Signup", func(t *testing.T) {
			defer hookRec.BeforeUserCreated.ClearCalls()

			email := "e2etesthooks_" + uuid.Must(uuid.NewV4()).String() + "@localhost"
			req := &api.SignupParams{
				Email:    email,
				Password: "password",
			}
			res := new(models.User)
			err := e2eapi.Do(ctx, http.MethodPost, apiSrv.URL+"/signup", req, res)
			require.NoError(t, err)
			require.Equal(t, email, res.Email.String())

			runBeforeUserCreated(t, res)
		})

		t.Run("SignupAnonymously", func(t *testing.T) {
			defer hookRec.BeforeUserCreated.ClearCalls()

			req := &api.SignupParams{}
			res := new(api.AccessTokenResponse)
			err := e2eapi.Do(ctx, http.MethodPost, apiSrv.URL+"/signup", req, res)
			require.NoError(t, err)

			runBeforeUserCreated(t, res.User)
		})

		t.Run("ExternalCallback", func(t *testing.T) {
			defer hookRec.BeforeUserCreated.ClearCalls()

			req := &api.SignupParams{}
			res := new(api.AccessTokenResponse)
			err := e2eapi.Do(ctx, http.MethodPost, apiSrv.URL+"/signup", req, res)
			require.NoError(t, err)

			runBeforeUserCreated(t, res.User)
		})

		t.Run("AdminEndpoints", func(t *testing.T) {
			t.Run("Invite", func(t *testing.T) {
				defer hookRec.BeforeUserCreated.ClearCalls()

				email := "e2etesthooks_" + uuid.Must(uuid.NewV4()).String() + "@localhost"
				req := &api.InviteParams{
					Email: email,
				}
				res := new(models.User)

				body := new(bytes.Buffer)
				err := json.NewEncoder(body).Encode(req)
				require.NoError(t, err)

				httpReq, err := http.NewRequestWithContext(
					ctx, "POST", "/invite", body)
				require.NoError(t, err)

				httpRes, err := inst.DoAdmin(httpReq)
				require.NoError(t, err)

				err = json.NewDecoder(httpRes.Body).Decode(res)
				require.NoError(t, err)

				runBeforeUserCreated(t, res)
			})

			t.Run("AdminGenerateLink", func(t *testing.T) {

				t.Run("SignupVerification", func(t *testing.T) {
					defer hookRec.BeforeUserCreated.ClearCalls()

					email := "e2etesthooks_" + uuid.Must(uuid.NewV4()).String() + "@localhost"
					req := &api.GenerateLinkParams{
						Type:     "signup",
						Email:    email,
						Password: "pass1234",
					}
					res := new(api.GenerateLinkResponse)

					body := new(bytes.Buffer)
					err := json.NewEncoder(body).Encode(req)
					require.NoError(t, err)

					httpReq, err := http.NewRequestWithContext(
						ctx, "POST", "/admin/generate_link", body)
					require.NoError(t, err)

					httpRes, err := inst.DoAdmin(httpReq)
					require.NoError(t, err)
					require.Equal(t, 200, httpRes.StatusCode)

					err = json.NewDecoder(httpRes.Body).Decode(res)
					require.NoError(t, err)

					runBeforeUserCreated(t, &res.User)
				})

				t.Run("InviteVerification", func(t *testing.T) {
					defer hookRec.BeforeUserCreated.ClearCalls()

					email := "e2etesthooks_" + uuid.Must(uuid.NewV4()).String() + "@localhost"
					req := &api.GenerateLinkParams{
						Type:  "invite",
						Email: email,
					}
					res := new(api.GenerateLinkResponse)

					body := new(bytes.Buffer)
					err := json.NewEncoder(body).Encode(req)
					require.NoError(t, err)

					httpReq, err := http.NewRequestWithContext(
						ctx, "POST", "/admin/generate_link", body)
					require.NoError(t, err)

					httpRes, err := inst.DoAdmin(httpReq)
					require.NoError(t, err)
					require.Equal(t, 200, httpRes.StatusCode)

					err = json.NewDecoder(httpRes.Body).Decode(res)
					require.NoError(t, err)
					dump.Dump(res)

					runBeforeUserCreated(t, &res.User)
				})
			})
		})
	})

	// Basic tests for CustomizeAccessToken
	t.Run("CustomizeAccessToken", func(t *testing.T) {
		require.NotNil(t, currentUser)

		type M = map[string]any

		copyMap := func(t *testing.T, m M) (out M) {
			b, err := json.Marshal(m)
			require.NoError(t, err)
			err = json.Unmarshal(b, &out)
			require.NoError(t, err)
			return out
		}
		checkClaims := func(t *testing.T, in, out M, exclude ...string) {
			if aud, ok := in["aud"].([]any); ok && len(aud) > 0 {
				require.Equal(t, aud[0].(string), out["aud"])
			}
			if aud, ok := in["aud"].(string); ok {
				require.Equal(t, aud, out["aud"])
			}

			for _, k := range []string{
				"iss",
				"sub",
				"exp",
				"iat",
				"aal",
				"role",
				"amr",
				"session_id",
				"is_anonymous",
				"app_metadata",
				"user_metadata",
				"phone",
				"email",
			} {
				if !slices.Contains(exclude, k) {
					require.Equal(t, in[k], out[k])
				}
			}
		}

		cases := []struct {
			desc   string
			from   func(claimsIn M) (claimsOut M)
			errStr string
			check  func(
				t *testing.T,
				claimsIn, claimsOut M,
			)
		}{
			{
				desc:   `empty claims`,
				from:   func(in M) M { return M{"claims": M{}} },
				errStr: "500: error generating jwt token",
			},

			{
				desc: `add app_metadata claims`,
				from: func(in M) M {
					out := copyMap(t, in)
					out["claims"].(M)["app_metadata"].(M)["bool_true"] = true
					out["claims"].(M)["app_metadata"].(M)["string_hello"] = "hello"
					return out
				},
				check: func(
					t *testing.T,
					in, out M,
				) {
					checkClaims(t, in, out, "app_metadata")

					for k := range in {
						if k == "app_metadata" {
							require.Equal(t,
								out["app_metadata"].(M)["bool_true"],
								true,
							)
							require.Equal(t,
								out["app_metadata"].(M)["string_hello"],
								"hello",
							)
							continue
						}
					}
				},
			},
		}

		for _, tc := range cases {
			t.Run(string(tc.desc), func(t *testing.T) {
				var claimsIn, claimsOut M
				hr := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("content-type", "application/json")
					w.WriteHeader(http.StatusOK)

					err := json.NewDecoder(r.Body).Decode(&claimsIn)
					require.NoError(t, err)

					claimsOut = tc.from(copyMap(t, claimsIn))
					err = json.NewEncoder(w).Encode(claimsOut)
					require.NoError(t, err)
				})

				hookRec.CustomizeAccessToken.ClearCalls()
				hookRec.CustomizeAccessToken.SetHandler(hr)
				req := &api.PasswordGrantParams{
					Email:    string(currentUser.Email),
					Password: "password",
				}

				res := new(api.AccessTokenResponse)
				err := e2eapi.Do(ctx, http.MethodPost, apiSrv.URL+"/token?grant_type=password", req, res)

				// always verify the hook request before checking response
				{
					calls := hookRec.CustomizeAccessToken.GetCalls()
					require.Equal(t, 1, len(calls))
					call := calls[0]

					hookReq := &v0hooks.CustomAccessTokenInput{}
					err := call.Unmarshal(hookReq)
					require.NoError(t, err)
					require.Equal(t, currentUser.ID, hookReq.UserID)
					require.Equal(t, currentUser.ID.String(), hookReq.Claims.Subject)
				}

				// check if we expected an error
				if tc.errStr != "" {
					require.Error(t, err)
					require.Contains(t, err.Error(), tc.errStr)
					return
				}
				require.True(t, len(res.Token) > 0)

				// parse the token we got back
				p := jwt.NewParser(jwt.WithValidMethods(globalCfg.JWT.ValidMethods))
				token, err := p.ParseWithClaims(
					res.Token,
					&api.AccessTokenClaims{},
					func(token *jwt.Token,
					) (any, error) {
						if kid, ok := token.Header["kid"]; ok {
							if kidStr, ok := kid.(string); ok {
								return conf.FindPublicKeyByKid(kidStr, &globalCfg.JWT)
							}
						}
						if alg, ok := token.Header["alg"]; ok {
							if alg == jwt.SigningMethodHS256.Name {
								// preserve backward compatibility for cases where the kid is not set
								return []byte(globalCfg.JWT.Secret), nil
							}
						}
						return nil, fmt.Errorf("missing kid")
					})
				require.NoError(t, err)

				tokenClaims := M{}
				{
					b, err := json.Marshal(token.Claims)
					require.NoError(t, err)
					err = json.Unmarshal(b, &tokenClaims)
					require.NoError(t, err)
				}

				if tc.check != nil {
					tc.check(t, claimsIn["claims"].(M), tokenClaims)
				}
			})
		}
	})
}
