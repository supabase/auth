package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/e2e"
	"github.com/supabase/auth/internal/e2e/e2eapi"
	"github.com/supabase/auth/internal/e2e/e2ehooks"
	"github.com/supabase/auth/internal/hooks/v0hooks"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
)

const defaultPassword = "password"

type M = map[string]any

func genEmail(suffixes ...string) string {
	uuid := uuid.Must(uuid.NewV4()).String()
	parts := []string{"e2e_test", uuid}
	parts = append(parts, suffixes...)
	name := strings.Join(parts, "_")
	return name + "@localhost"
}

func genPhone() string {
	var sb strings.Builder
	sb.WriteString("1")
	for range 9 {
		// #nosec G404
		sb.WriteString(fmt.Sprintf("%d", rand.Intn(9)))
	}
	phone := sb.String()
	return phone
}

func runVerifyBeforeUserCreatedHook(
	t *testing.T,
	inst *e2ehooks.Instance,
	expUser *models.User,
) *models.User {
	var latest *models.User
	t.Run("VerifyBeforeUserCreatedHook", func(t *testing.T) {
		defer inst.HookRecorder.BeforeUserCreated.ClearCalls()

		calls := inst.HookRecorder.BeforeUserCreated.GetCalls()
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

		latest, err = models.FindUserByID(inst.Conn, expUser.ID)
		require.NoError(t, err)
		require.NotNil(t, latest)
	})
	return latest
}

func runVerifyAfterUserCreatedHook(
	t *testing.T,
	inst *e2ehooks.Instance,
	expUser *models.User,
) *models.User {
	var latest *models.User
	t.Run("VerifyAfterUserCreatedHook", func(t *testing.T) {
		defer inst.HookRecorder.AfterUserCreated.ClearCalls()

		calls := inst.HookRecorder.AfterUserCreated.GetCalls()
		require.Equal(t, 1, len(calls))
		call := calls[0]

		hookReq := &v0hooks.AfterUserCreatedInput{}
		err := call.Unmarshal(hookReq)
		require.NoError(t, err)
		require.Equal(t, v0hooks.AfterUserCreated, hookReq.Metadata.Name)

		u := hookReq.User
		require.Equal(t, expUser.ID, u.ID)
		require.Equal(t, expUser.Aud, u.Aud)
		require.Equal(t, expUser.Email, u.Email)
		require.Equal(t, expUser.AppMetaData, u.AppMetaData)

		require.False(t, u.CreatedAt.IsZero())
		require.False(t, u.UpdatedAt.IsZero())

		err = expUser.Confirm(inst.Conn)
		require.NoError(t, err)

		latest, err = models.FindUserByID(inst.Conn, expUser.ID)
		require.NoError(t, err)
		require.NotNil(t, latest)
	})
	return latest
}

func getAccessToken(
	ctx context.Context,
	t *testing.T,
	inst *e2ehooks.Instance,
	email, pass string,
) *api.AccessTokenResponse {
	req := &api.PasswordGrantParams{
		Email:    email,
		Password: pass,
	}

	res := new(api.AccessTokenResponse)
	err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/token?grant_type=password", req, res)
	require.NoError(t, err)
	return res
}
func signupAndConfirm(
	ctx context.Context,
	t *testing.T,
	inst *e2ehooks.Instance,
) *models.User {
	defer inst.HookRecorder.SendEmail.ClearCalls()

	// signup user
	email := genEmail()
	req := &api.SignupParams{
		Email:    email,
		Password: defaultPassword,
	}
	expUser := new(models.User)
	err := e2eapi.Do(
		ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, expUser)
	require.NoError(t, err)
	require.Equal(t, email, expUser.Email.String())

	// load the hook call
	calls := inst.HookRecorder.SendEmail.GetCalls()
	require.Equal(t, 1, len(calls))
	call := calls[0]

	hookReq := &v0hooks.SendEmailInput{}
	err = call.Unmarshal(hookReq)
	require.NoError(t, err)

	// verify that the latest user from find user matches OTP
	otpHash := crypto.GenerateTokenHash(
		expUser.GetEmail(), hookReq.EmailData.Token)
	require.NotEmpty(t, hookReq.EmailData.Token)
	require.Equal(t, otpHash, hookReq.EmailData.TokenHash)

	// hook user matches the signup user
	require.Equal(t, expUser.ID, hookReq.User.ID)
	require.Equal(t, expUser.ID, hookReq.User.ID)
	require.Equal(t, expUser.Aud, hookReq.User.Aud)
	require.Equal(t, expUser.Email, hookReq.User.Email)
	require.Equal(t, expUser.AppMetaData, hookReq.User.AppMetaData)

	// otp matches the user id and email
	ott, err := models.FindOneTimeToken(
		inst.Conn,
		hookReq.EmailData.TokenHash,
		models.ConfirmationToken)
	require.NoError(t, err)
	require.Equal(t, expUser.ID.String(), ott.UserID.String())
	require.Equal(t, expUser.Email.String(), ott.RelatesTo)

	// OTP token user matches our signup user
	hookUser, err := models.FindUserByConfirmationToken(
		inst.Conn, hookReq.EmailData.TokenHash)
	require.NoError(t, err)
	require.Equal(t, expUser.ID, hookUser.ID)
	require.Equal(t, expUser.Email, hookUser.Email)

	// construct email data we expect, except for OTP
	expData := mailer.EmailData{
		// note: we already validated token by generating token hash
		Token: hookReq.EmailData.Token,

		TokenHash:       ott.TokenHash,
		RedirectTo:      inst.Config.SiteURL,
		EmailActionType: mailer.SignupVerification,
		SiteURL:         inst.Config.API.ExternalURL,
		TokenNew:        "",
		TokenHashNew:    "",
	}
	require.Equal(t, expData, hookReq.EmailData)

	// Verify this user
	err = hookUser.Confirm(inst.Conn)
	require.NoError(t, err)

	return hookUser
}

func TestE2EHooks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	t.Run("UserHooks", func(t *testing.T) {
		globalCfg := e2e.Must(e2e.Config())
		globalCfg.External.AnonymousUsers.Enabled = true
		globalCfg.External.Phone.Enabled = true

		inst, err := e2ehooks.New(globalCfg)
		require.NoError(t, err)
		defer inst.Close()

		t.Run("SignupEmail", func(t *testing.T) {
			defer inst.HookRecorder.BeforeUserCreated.ClearCalls()

			email := genEmail()
			req := &api.SignupParams{
				Email:    email,
				Password: defaultPassword,
			}
			res := new(models.User)
			err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, res)
			require.NoError(t, err)
			require.Equal(t, email, res.Email.String())

			runVerifyBeforeUserCreatedHook(t, inst, res)
			runVerifyAfterUserCreatedHook(t, inst, res)
		})

		t.Run("SignupPhone", func(t *testing.T) {
			defer inst.HookRecorder.BeforeUserCreated.ClearCalls()

			phone := genPhone()
			req := &api.SignupParams{
				Phone:    phone,
				Password: defaultPassword,
			}
			res := new(models.User)
			err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, res)
			require.NoError(t, err)
			require.Equal(t, phone, res.Phone.String())

			runVerifyBeforeUserCreatedHook(t, inst, res)
			runVerifyAfterUserCreatedHook(t, inst, res)

		})

		t.Run("SignupAnonymously", func(t *testing.T) {
			defer inst.HookRecorder.BeforeUserCreated.ClearCalls()

			req := &api.SignupParams{}
			res := new(api.AccessTokenResponse)
			err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, res)
			require.NoError(t, err)

			runVerifyBeforeUserCreatedHook(t, inst, res.User)
			runVerifyAfterUserCreatedHook(t, inst, res.User)

		})

		t.Run("ExternalCallback", func(t *testing.T) {
			defer inst.HookRecorder.BeforeUserCreated.ClearCalls()

			req := &api.SignupParams{}
			res := new(api.AccessTokenResponse)
			err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, res)
			require.NoError(t, err)

			runVerifyBeforeUserCreatedHook(t, inst, res.User)
			runVerifyAfterUserCreatedHook(t, inst, res.User)

		})

		t.Run("AdminEndpoints", func(t *testing.T) {
			t.Run("Invite", func(t *testing.T) {
				defer inst.HookRecorder.BeforeUserCreated.ClearCalls()

				email := genEmail()
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

				runVerifyBeforeUserCreatedHook(t, inst, res)
				runVerifyAfterUserCreatedHook(t, inst, res)

			})

			t.Run("AdminGenerateLink", func(t *testing.T) {

				t.Run("SignupVerification", func(t *testing.T) {
					defer inst.HookRecorder.BeforeUserCreated.ClearCalls()

					email := genEmail()
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

					runVerifyBeforeUserCreatedHook(t, inst, &res.User)
					runVerifyAfterUserCreatedHook(t, inst, &res.User)
				})

				t.Run("InviteVerification", func(t *testing.T) {
					defer inst.HookRecorder.BeforeUserCreated.ClearCalls()

					email := genEmail()
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

					runVerifyBeforeUserCreatedHook(t, inst, &res.User)
					runVerifyAfterUserCreatedHook(t, inst, &res.User)
				})
			})
		})
	})

	t.Run("MFAVerificationAttempt", func(t *testing.T) {
		globalCfg := e2e.Must(e2e.Config())
		globalCfg.MFA.TOTP.EnrollEnabled = true
		globalCfg.MFA.Phone.EnrollEnabled = true
		globalCfg.MFA.Phone.VerifyEnabled = true

		inst, err := e2ehooks.New(globalCfg)
		require.NoError(t, err)
		defer inst.Close()

		type flowResult struct {
			factorRes          *api.EnrollFactorResponse
			challengeRes       *api.ChallengeFactorResponse
			mfaUser            *models.User
			mfaUserAccessToken *api.AccessTokenResponse
		}

		runMFAFlow := func(t *testing.T) *flowResult {
			factorRes := new(api.EnrollFactorResponse)
			challengeRes := new(api.ChallengeFactorResponse)
			mfaUser := new(models.User)
			mfaUserAccessToken := new(api.AccessTokenResponse)

			t.Run("MFAFlow", func(t *testing.T) {
				t.Run("Signup", func(t *testing.T) {
					email := genEmail()
					req := &api.SignupParams{
						Email:    email,
						Password: defaultPassword,
					}
					err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, mfaUser)
					require.NoError(t, err)
					require.Equal(t, email, mfaUser.Email.String())

					mfaUser = runVerifyBeforeUserCreatedHook(t, inst, mfaUser)
					runVerifyAfterUserCreatedHook(t, inst, mfaUser)
					require.NotNil(t, mfaUser)
					mfaUserAccessToken = getAccessToken(
						ctx, t, inst, string(mfaUser.Email), defaultPassword)

					phone := genPhone()
					domain := strings.Split(email, "@")[1]

					// enroll factor
					t.Run("MFAEnroll", func(t *testing.T) {
						req := &api.EnrollFactorParams{
							FriendlyName: "totp_" + email,
							Phone:        phone,
							Issuer:       domain,
							FactorType:   models.TOTP,
						}

						body := new(bytes.Buffer)
						err = json.NewEncoder(body).Encode(req)
						require.NoError(t, err)

						httpReq, err := http.NewRequestWithContext(
							ctx, "POST", "/factors/", body)
						require.NoError(t, err)

						httpRes, err := inst.DoAuth(httpReq, mfaUserAccessToken.Token)
						require.NoError(t, err)
						require.Equal(t, 200, httpRes.StatusCode)

						err = json.NewDecoder(httpRes.Body).Decode(factorRes)
						require.NoError(t, err)
					})

					// challenge factor
					t.Run("MFAChallenge", func(t *testing.T) {
						req := &models.Factor{
							ID: factorRes.ID,
						}

						body := new(bytes.Buffer)
						err = json.NewEncoder(body).Encode(req)
						require.NoError(t, err)

						url := fmt.Sprintf("/factors/%v/challenge", factorRes.ID)
						httpReq, err := http.NewRequestWithContext(
							ctx, "POST", url, body)
						require.NoError(t, err)

						httpRes, err := inst.DoAuth(httpReq, mfaUserAccessToken.Token)
						require.NoError(t, err)
						require.Equal(t, 200, httpRes.StatusCode)

						err = json.NewDecoder(httpRes.Body).Decode(challengeRes)
						require.NoError(t, err)
					})
				})
			})
			return &flowResult{
				factorRes:          factorRes,
				challengeRes:       challengeRes,
				mfaUser:            mfaUser,
				mfaUserAccessToken: mfaUserAccessToken,
			}
		}

		t.Run("MFAVerifySuccess", func(t *testing.T) {
			defer inst.HookRecorder.MFAVerification.ClearCalls()

			flowRes := runMFAFlow(t)
			verifyRes := new(api.AccessTokenResponse)

			mfaCode, err := totp.GenerateCode(flowRes.factorRes.TOTP.Secret, time.Now().UTC())
			require.NoError(t, err)

			req := &api.VerifyFactorParams{
				ChallengeID: flowRes.challengeRes.ID,
				Code:        mfaCode,
			}

			body := new(bytes.Buffer)
			err = json.NewEncoder(body).Encode(req)
			require.NoError(t, err)

			url := fmt.Sprintf("/factors/%v/verify", flowRes.factorRes.ID)
			httpReq, err := http.NewRequestWithContext(
				ctx, "POST", url, body)
			require.NoError(t, err)

			httpRes, err := inst.DoAuth(httpReq, flowRes.mfaUserAccessToken.Token)
			require.NoError(t, err)
			require.Equal(t, 200, httpRes.StatusCode)

			// verify the mfa was accepted
			err = json.NewDecoder(httpRes.Body).Decode(verifyRes)
			require.NoError(t, err)
			require.NotEmpty(t, verifyRes.Token)

			calls := inst.HookRecorder.MFAVerification.GetCalls()
			require.Equal(t, 1, len(calls))
			call := calls[0]

			hookReq := M{}
			err = call.Unmarshal(&hookReq)
			require.NoError(t, err)

			// verify hook request
			require.Equal(t, flowRes.factorRes.ID.String(), hookReq["factor_id"])
			require.Equal(t, flowRes.factorRes.Type, hookReq["factor_type"])
			require.Equal(t, flowRes.mfaUser.ID.String(), hookReq["user_id"])
			require.Equal(t, true, hookReq["valid"])
		})

		t.Run("MFAVerifyFailure", func(t *testing.T) {
			defer inst.HookRecorder.MFAVerification.ClearCalls()

			const errorMsg = "sentinel error message"
			{
				hr := e2ehooks.HandleJSON(M{
					"decision": "reject",
					"message":  errorMsg,
				})
				inst.HookRecorder.MFAVerification.SetHandler(hr)
			}

			flowRes := runMFAFlow(t)
			errorRes := new(api.HTTPError)

			mfaCode, err := totp.GenerateCode(flowRes.factorRes.TOTP.Secret, time.Now().UTC())
			require.NoError(t, err)

			req := &api.VerifyFactorParams{
				ChallengeID: flowRes.challengeRes.ID,
				Code:        mfaCode,
			}

			body := new(bytes.Buffer)
			err = json.NewEncoder(body).Encode(req)
			require.NoError(t, err)

			url := fmt.Sprintf("/factors/%v/verify", flowRes.factorRes.ID)
			httpReq, err := http.NewRequestWithContext(
				ctx, "POST", url, body)
			require.NoError(t, err)

			httpRes, err := inst.DoAuth(httpReq, flowRes.mfaUserAccessToken.Token)
			require.NoError(t, err)
			require.Equal(t, 403, httpRes.StatusCode)

			// verify the mfa rejection
			err = json.NewDecoder(httpRes.Body).Decode(errorRes)
			require.NoError(t, err)
			require.Equal(t, 403, errorRes.HTTPStatus)
			require.Equal(t, "mfa_verification_rejected", errorRes.ErrorCode)
			require.Equal(t, errorMsg, errorRes.Message)

			calls := inst.HookRecorder.MFAVerification.GetCalls()
			require.Equal(t, 1, len(calls))
			call := calls[0]

			hookReq := M{}
			err = call.Unmarshal(&hookReq)
			require.NoError(t, err)

			// verify hook request
			require.Equal(t, flowRes.factorRes.ID.String(), hookReq["factor_id"])
			require.Equal(t, flowRes.factorRes.Type, hookReq["factor_type"])
			require.Equal(t, flowRes.mfaUser.ID.String(), hookReq["user_id"])
			require.Equal(t, true, hookReq["valid"])
		})
	})

	t.Run("CustomizeAccessToken", func(t *testing.T) {
		globalCfg := e2e.Must(e2e.Config())
		inst, err := e2ehooks.New(globalCfg)
		require.NoError(t, err)
		defer inst.Close()

		// setup user to test with
		var currentUser *models.User
		{
			email := genEmail()
			req := &api.SignupParams{
				Email:    email,
				Password: defaultPassword,
			}
			res := new(models.User)
			err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, res)
			require.NoError(t, err)
			require.Equal(t, email, res.Email.String())

			currentUser = runVerifyBeforeUserCreatedHook(t, inst, res)
			runVerifyAfterUserCreatedHook(t, inst, res)
			require.NotNil(t, currentUser)
			inst.HookRecorder.CustomizeAccessToken.ClearCalls()
		}

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
				desc:   `claims field missing`,
				from:   func(in M) M { return M{} },
				errStr: "500: output claims field is missing",
			},

			{
				desc: `claims field missing with top level keys`,
				from: func(in M) M {
					return M{
						"myclaim":     "aaa",
						"other_claim": "bbb",
					}
				},
				errStr: "500: output claims field is missing",
			},

			{
				desc:   `claims field nil`,
				from:   func(in M) M { return M{"claims": nil} },
				errStr: "500: output claims do not conform to the expected schema",
			},

			{
				desc:   `claims field empty`,
				from:   func(in M) M { return M{"claims": M{}} },
				errStr: "500: output claims do not conform to the expected schema",
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
				defer inst.HookRecorder.CustomizeAccessToken.ClearCalls()

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

				inst.HookRecorder.CustomizeAccessToken.ClearCalls()
				inst.HookRecorder.CustomizeAccessToken.SetHandler(hr)
				req := &api.PasswordGrantParams{
					Email:    string(currentUser.Email),
					Password: defaultPassword,
				}

				res := new(api.AccessTokenResponse)
				err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/token?grant_type=password", req, res)

				// always verify the hook request before checking response
				{
					calls := inst.HookRecorder.CustomizeAccessToken.GetCalls()
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

	t.Run("SendEmail", func(t *testing.T) {
		t.Run("Confirmation", func(t *testing.T) {
			globalCfg := e2e.Must(e2e.Config())
			inst, err := e2ehooks.New(globalCfg)
			require.NoError(t, err)
			defer inst.Close()

			signupAndConfirm(ctx, t, inst)
		})

		t.Run("SecureEmailChange=Enabled", func(t *testing.T) {
			globalCfg := e2e.Must(e2e.Config())
			globalCfg.External.AnonymousUsers.Enabled = true
			globalCfg.Mailer.SecureEmailChangeEnabled = true

			t.Run("EmailChange", func(t *testing.T) {
				inst, err := e2ehooks.New(globalCfg)
				require.NoError(t, err)
				defer inst.Close()

				// test requires this flag
				require.True(t, inst.Config.Mailer.SecureEmailChangeEnabled)

				signupUser := signupAndConfirm(ctx, t, inst)
				currentUser := signupUser

				// get access token
				currentAccessToken := getAccessToken(
					ctx, t, inst, string(currentUser.Email), defaultPassword)

				// update email
				curEmail := signupUser.Email.String()
				newEmail := genEmail("new-email")
				{
					req := &api.UserUpdateParams{
						Email: newEmail,
					}
					res := new(models.User)

					body := new(bytes.Buffer)
					err = json.NewEncoder(body).Encode(req)
					require.NoError(t, err)

					httpReq, err := http.NewRequestWithContext(
						ctx, "PUT", "/user", body)
					require.NoError(t, err)

					httpRes, err := inst.DoAuth(httpReq, currentAccessToken.Token)
					require.NoError(t, err)
					require.Equal(t, 200, httpRes.StatusCode)

					err = json.NewDecoder(httpRes.Body).Decode(res)
					require.NoError(t, err)

					currentUser = res
				}

				// verify email change is set
				require.Equal(t, curEmail, currentUser.Email.String())
				require.Equal(t, newEmail, currentUser.EmailChange)

				// load the hook call
				calls := inst.HookRecorder.SendEmail.GetCalls()
				require.Equal(t, 1, len(calls))
				call := calls[0]

				hookReq := &v0hooks.SendEmailInput{}
				err = call.Unmarshal(hookReq)
				require.NoError(t, err)

				// hook user matches the signup user
				require.Equal(t, signupUser.ID, hookReq.User.ID)
				require.Equal(t, signupUser.Aud, hookReq.User.Aud)
				require.Equal(t, signupUser.Email, hookReq.User.Email)
				require.Equal(t, signupUser.AppMetaData, hookReq.User.AppMetaData)

				// should have old and new token for email change with secure
				// email change flag enabled
				require.NotEmpty(t, hookReq.EmailData.Token)
				require.NotEmpty(t, hookReq.EmailData.TokenNew)

				// verify new and prev emails
				require.Equal(t, curEmail, hookReq.User.Email.String())
				require.Equal(t, newEmail, hookReq.User.EmailChange)

				// verify otps
				curOtpHash := crypto.GenerateTokenHash(
					curEmail, hookReq.EmailData.Token)
				newOtpHash := crypto.GenerateTokenHash(
					newEmail, hookReq.EmailData.TokenNew)

				// The hashes are switched incorrectly in the current code, i.e.:
				//
				// 	EmailData.TokenHashNew = Hash(CurEmail, EmailData.Token)
				// 	EmailData.TokenHash    = Hash(NewEmail, EmailData.TokenNew)
				//
				// This check locks this behavior in to keep BC with existing hooks
				require.Equal(t, newOtpHash, hookReq.EmailData.TokenHash)
				require.Equal(t, curOtpHash, hookReq.EmailData.TokenHashNew)

				// hook user matches the signup user
				require.Equal(t, signupUser.ID, hookReq.User.ID)
				require.Equal(t, signupUser.ID, hookReq.User.ID)
				require.Equal(t, signupUser.Aud, hookReq.User.Aud)
				require.Equal(t, signupUser.Email, hookReq.User.Email)
				require.Equal(t, signupUser.AppMetaData, hookReq.User.AppMetaData)

				// verify there is an ott generated
				ott, err := models.FindOneTimeToken(
					inst.Conn,
					hookReq.EmailData.TokenHash,
					models.EmailChangeTokenNew)
				require.NoError(t, err)
				require.Equal(t, signupUser.ID.String(), ott.UserID.String())
				require.Equal(t, newEmail, ott.RelatesTo)

				// verify the EmailData
				require.Equal(t, mailer.EmailChangeVerification, hookReq.EmailData.EmailActionType)
				require.Equal(t, inst.Config.SiteURL, hookReq.EmailData.RedirectTo)
				require.Equal(t, inst.Config.API.ExternalURL, hookReq.EmailData.SiteURL)
			})

			t.Run("EmailChangeAnonymous", func(t *testing.T) {
				inst, err := e2ehooks.New(globalCfg)
				require.NoError(t, err)
				defer inst.Close()

				// test requires this flag
				require.True(t, inst.Config.Mailer.SecureEmailChangeEnabled)

				// signup anon
				var accessToken *api.AccessTokenResponse
				{
					req := &api.SignupParams{}
					res := new(api.AccessTokenResponse)
					err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, res)
					require.NoError(t, err)
					accessToken = res
				}

				// update email
				signupUser := accessToken.User
				currentUser := signupUser
				newEmail := genEmail("new")
				{
					pass := defaultPassword
					req := &api.UserUpdateParams{
						Email:    newEmail,
						Password: &pass,
					}
					res := new(models.User)

					body := new(bytes.Buffer)
					err = json.NewEncoder(body).Encode(req)
					require.NoError(t, err)

					httpReq, err := http.NewRequestWithContext(
						ctx, "PUT", "/user", body)
					require.NoError(t, err)

					httpRes, err := inst.DoAuth(httpReq, accessToken.Token)
					require.NoError(t, err)
					require.Equal(t, 200, httpRes.StatusCode)

					err = json.NewDecoder(httpRes.Body).Decode(res)
					require.NoError(t, err)

					currentUser = res
				}

				// verify current & new email fields
				require.Equal(t, "", currentUser.Email.String())
				require.Equal(t, newEmail, currentUser.EmailChange)

				// load the hook call
				calls := inst.HookRecorder.SendEmail.GetCalls()
				require.Equal(t, 1, len(calls))
				call := calls[0]

				hookReq := &v0hooks.SendEmailInput{}
				err = call.Unmarshal(hookReq)
				require.NoError(t, err)

				// verify there is an ott generated
				ott, err := models.FindOneTimeToken(
					inst.Conn,
					hookReq.EmailData.TokenHash,
					models.EmailChangeTokenNew)
				require.NoError(t, err)
				require.Equal(t, signupUser.ID.String(), ott.UserID.String())
				require.Equal(t, newEmail, ott.RelatesTo)

				// hook user matches the signup user
				require.Equal(t, signupUser.ID, hookReq.User.ID)
				require.Equal(t, signupUser.Aud, hookReq.User.Aud)
				require.Equal(t, signupUser.Email, hookReq.User.Email)
				require.Equal(t, signupUser.AppMetaData, hookReq.User.AppMetaData)

				// verify the new_email field in hook req
				require.Equal(t, newEmail, hookReq.User.EmailChange)

				// BUG(cstockton): verify the token is moved TokenNew -> Token
				require.NotEmpty(t, hookReq.EmailData.Token)

				// BUG(cstockton): verify that token new is empty like before
				require.Empty(t, hookReq.EmailData.TokenNew)
				require.Empty(t, hookReq.EmailData.TokenHashNew)

				// verify otps
				newOtpHash := crypto.GenerateTokenHash(
					newEmail, hookReq.EmailData.Token)

				// The new email is stored on fields without _new suffix.
				//
				// 	EmailData.TokenHash = Hash(NewEmail, EmailData.TokenNew)
				//
				// This check locks this behavior in to keep BC with existing hooks
				require.Equal(t, newOtpHash, hookReq.EmailData.TokenHash)

				// verify the EmailData
				require.Equal(t, mailer.EmailChangeVerification, hookReq.EmailData.EmailActionType)
				require.Equal(t, inst.Config.SiteURL, hookReq.EmailData.RedirectTo)
				require.Equal(t, inst.Config.API.ExternalURL, hookReq.EmailData.SiteURL)
			})
		})

		t.Run("SecureEmailChange=Disabled", func(t *testing.T) {
			globalCfg := e2e.Must(e2e.Config())
			globalCfg.External.AnonymousUsers.Enabled = true
			globalCfg.Mailer.SecureEmailChangeEnabled = false

			t.Run("EmailChange", func(t *testing.T) {
				inst, err := e2ehooks.New(globalCfg)
				require.NoError(t, err)
				defer inst.Close()

				// test requires this flag
				require.False(t, inst.Config.Mailer.SecureEmailChangeEnabled)

				signupUser := signupAndConfirm(ctx, t, inst)
				currentUser := signupUser

				// get access token
				currentAccessToken := getAccessToken(
					ctx, t, inst, string(currentUser.Email), defaultPassword)

				// update email
				curEmail := signupUser.Email.String()
				newEmail := genEmail("new-email")
				{
					req := &api.UserUpdateParams{
						Email: newEmail,
					}
					res := new(models.User)

					body := new(bytes.Buffer)
					err = json.NewEncoder(body).Encode(req)
					require.NoError(t, err)

					httpReq, err := http.NewRequestWithContext(
						ctx, "PUT", "/user", body)
					require.NoError(t, err)

					httpRes, err := inst.DoAuth(httpReq, currentAccessToken.Token)
					require.NoError(t, err)
					require.Equal(t, 200, httpRes.StatusCode)

					err = json.NewDecoder(httpRes.Body).Decode(res)
					require.NoError(t, err)

					currentUser = res
				}

				// verify email change is set
				require.Equal(t, curEmail, currentUser.Email.String())
				require.Equal(t, newEmail, currentUser.EmailChange)

				// load the hook call
				calls := inst.HookRecorder.SendEmail.GetCalls()
				require.Equal(t, 1, len(calls))
				call := calls[0]

				hookReq := &v0hooks.SendEmailInput{}
				err = call.Unmarshal(hookReq)
				require.NoError(t, err)

				// hook user matches the signup user
				require.Equal(t, signupUser.ID, hookReq.User.ID)
				require.Equal(t, signupUser.Aud, hookReq.User.Aud)
				require.Equal(t, signupUser.Email, hookReq.User.Email)
				require.Equal(t, signupUser.AppMetaData, hookReq.User.AppMetaData)

				// should have old and new token for email change with secure
				// email change flag enabled
				require.NotEmpty(t, hookReq.EmailData.Token)
				require.Empty(t, hookReq.EmailData.TokenNew)
				require.Empty(t, hookReq.EmailData.TokenHashNew)

				// verify new and prev emails
				require.Equal(t, curEmail, hookReq.User.Email.String())
				require.Equal(t, newEmail, hookReq.User.EmailChange)

				// verify otps
				newOtpHash := crypto.GenerateTokenHash(
					newEmail, hookReq.EmailData.Token)

				// The new email is stored on fields without _new suffix.
				//
				// 	EmailData.TokenHash = Hash(NewEmail, EmailData.TokenNew)
				//
				// This check locks this behavior in to keep BC with existing hooks
				require.Equal(t, newOtpHash, hookReq.EmailData.TokenHash)

				// hook user matches the signup user
				require.Equal(t, signupUser.ID, hookReq.User.ID)
				require.Equal(t, signupUser.ID, hookReq.User.ID)
				require.Equal(t, signupUser.Aud, hookReq.User.Aud)
				require.Equal(t, signupUser.Email, hookReq.User.Email)
				require.Equal(t, signupUser.AppMetaData, hookReq.User.AppMetaData)

				// verify there is an ott generated
				ott, err := models.FindOneTimeToken(
					inst.Conn,
					hookReq.EmailData.TokenHash,
					models.EmailChangeTokenNew)
				require.NoError(t, err)
				require.Equal(t, signupUser.ID.String(), ott.UserID.String())
				require.Equal(t, newEmail, ott.RelatesTo)

				// verify the EmailData
				require.Equal(t, mailer.EmailChangeVerification, hookReq.EmailData.EmailActionType)
				require.Equal(t, inst.Config.SiteURL, hookReq.EmailData.RedirectTo)
				require.Equal(t, inst.Config.API.ExternalURL, hookReq.EmailData.SiteURL)
			})

			t.Run("EmailChangeAnonymous", func(t *testing.T) {
				inst, err := e2ehooks.New(globalCfg)
				require.NoError(t, err)
				defer inst.Close()

				// test requires this flag
				require.False(t, inst.Config.Mailer.SecureEmailChangeEnabled)

				// signup anon
				var accessToken *api.AccessTokenResponse
				{
					req := &api.SignupParams{}
					res := new(api.AccessTokenResponse)
					err := e2eapi.Do(ctx, http.MethodPost, inst.APIServer.URL+"/signup", req, res)
					require.NoError(t, err)
					accessToken = res
				}

				// update email
				signupUser := accessToken.User
				currentUser := signupUser
				newEmail := genEmail("new")
				{
					pass := defaultPassword
					req := &api.UserUpdateParams{
						Email:    newEmail,
						Password: &pass,
					}
					res := new(models.User)

					body := new(bytes.Buffer)
					err = json.NewEncoder(body).Encode(req)
					require.NoError(t, err)

					httpReq, err := http.NewRequestWithContext(
						ctx, "PUT", "/user", body)
					require.NoError(t, err)

					httpRes, err := inst.DoAuth(httpReq, accessToken.Token)
					require.NoError(t, err)
					require.Equal(t, 200, httpRes.StatusCode)

					err = json.NewDecoder(httpRes.Body).Decode(res)
					require.NoError(t, err)

					currentUser = res
				}

				// verify current & new email fields
				require.Equal(t, "", currentUser.Email.String())
				require.Equal(t, newEmail, currentUser.EmailChange)

				// load the hook call
				calls := inst.HookRecorder.SendEmail.GetCalls()
				require.Equal(t, 1, len(calls))
				call := calls[0]

				hookReq := &v0hooks.SendEmailInput{}
				err = call.Unmarshal(hookReq)
				require.NoError(t, err)

				// verify there is an ott generated
				ott, err := models.FindOneTimeToken(
					inst.Conn,
					hookReq.EmailData.TokenHash,
					models.EmailChangeTokenNew)
				require.NoError(t, err)
				require.Equal(t, signupUser.ID.String(), ott.UserID.String())
				require.Equal(t, newEmail, ott.RelatesTo)

				// hook user matches the signup user
				require.Equal(t, signupUser.ID, hookReq.User.ID)
				require.Equal(t, signupUser.Aud, hookReq.User.Aud)
				require.Equal(t, signupUser.Email, hookReq.User.Email)
				require.Equal(t, signupUser.AppMetaData, hookReq.User.AppMetaData)

				// verify the new_email field in hook req
				require.Equal(t, newEmail, hookReq.User.EmailChange)

				// BUG(cstockton): verify the token is moved TokenNew -> Token
				require.NotEmpty(t, hookReq.EmailData.Token)

				// BUG(cstockton): verify that token new is empty like before
				require.Empty(t, hookReq.EmailData.TokenNew)
				require.Empty(t, hookReq.EmailData.TokenHashNew)

				// verify otps
				newOtpHash := crypto.GenerateTokenHash(
					newEmail, hookReq.EmailData.Token)

				// The new email is stored on fields without _new suffix.
				//
				// 	EmailData.TokenHash = Hash(NewEmail, EmailData.TokenNew)
				//
				// This check locks this behavior in to keep BC with existing hooks
				require.Equal(t, newOtpHash, hookReq.EmailData.TokenHash)

				// verify the EmailData
				require.Equal(t, mailer.EmailChangeVerification, hookReq.EmailData.EmailActionType)
				require.Equal(t, inst.Config.SiteURL, hookReq.EmailData.RedirectTo)
				require.Equal(t, inst.Config.API.ExternalURL, hookReq.EmailData.SiteURL)
			})
		})
	})
}
