package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/supabase/auth/internal/api/sms_provider"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/mailer/mockclient"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/models"
)

type SignupTestSuite struct {
	suite.Suite
	API    *API
	Config *conf.GlobalConfiguration
}

func TestSignup(t *testing.T) {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)

	ts := &SignupTestSuite{
		API:    api,
		Config: config,
	}
	defer api.db.Close()

	suite.Run(t, ts)
}

func (ts *SignupTestSuite) SetupTest() {
	models.TruncateAll(ts.API.db)
}

// TestSignup tests API /signup route
func (ts *SignupTestSuite) TestSignup() {
	// Request body
	var buffer bytes.Buffer
	require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
		"email":    "test@example.com",
		"password": "test123",
		"data": map[string]interface{}{
			"a": 1,
		},
	}))

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusOK, w.Code)

	data := models.User{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	assert.Equal(ts.T(), "test@example.com", data.GetEmail())
	assert.Equal(ts.T(), ts.Config.JWT.Aud, data.Aud)
	assert.Equal(ts.T(), 1.0, data.UserMetaData["a"])
	assert.Equal(ts.T(), "email", data.AppMetaData["provider"])
	assert.Equal(ts.T(), []interface{}{"email"}, data.AppMetaData["providers"])
}

// TestSignupTwice checks to make sure the same email cannot be registered twice
func (ts *SignupTestSuite) TestSignupTwice() {
	// Request body
	var buffer bytes.Buffer

	encode := func() {
		require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(map[string]interface{}{
			"email":    "test1@example.com",
			"password": "test123",
			"data": map[string]interface{}{
				"a": 1,
			},
		}))
	}

	encode()

	// Setup request
	req := httptest.NewRequest(http.MethodPost, "http://localhost/signup", &buffer)
	req.Header.Set("Content-Type", "application/json")

	// Setup response recorder
	w := httptest.NewRecorder()
	y := httptest.NewRecorder()

	ts.API.handler.ServeHTTP(y, req)
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test1@example.com", ts.Config.JWT.Aud)
	if err == nil {
		require.NoError(ts.T(), u.Confirm(ts.API.db))
	}

	encode()
	ts.API.handler.ServeHTTP(w, req)

	data := models.User{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

	require.Equal(ts.T(), http.StatusOK, w.Code)

	assert.NotEqual(ts.T(), u.ID, data.ID)
	assert.Equal(ts.T(), "test1@example.com", data.GetEmail())
	assert.Equal(ts.T(), ts.Config.JWT.Aud, data.Aud)
	assert.Equal(ts.T(), 1.0, data.UserMetaData["a"])
	assert.Equal(ts.T(), "email", data.AppMetaData["provider"])
	assert.Equal(ts.T(), []interface{}{"email"}, data.AppMetaData["providers"])
}

func (ts *SignupTestSuite) TestSignupTwiceResponse() {
	phoneEnabled := ts.Config.External.Phone.Enabled
	ts.Config.External.Phone.Enabled = true
	defer func() { ts.Config.External.Phone.Enabled = phoneEnabled }()

	user, err := models.NewUser("123456789", "repeat@example.com", "password", ts.Config.JWT.Aud, map[string]interface{}{"full_name": "Test User"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(user))
	require.NoError(ts.T(), user.Confirm(ts.API.db))
	require.NoError(ts.T(), user.ConfirmPhone(ts.API.db))

	past := time.Now().Add(-24 * time.Hour)
	bannedUntil := time.Now().Add(24 * time.Hour)
	user.InvitedAt = &past
	user.RecoverySentAt = &past
	user.PhoneChange = "987654321"
	user.PhoneChangeSentAt = &past
	user.ReauthenticationSentAt = &past
	user.BannedUntil = &bannedUntil
	require.NoError(ts.T(), ts.API.db.UpdateOnly(user, "invited_at", "recovery_sent_at", "phone_change", "phone_change_sent_at", "reauthentication_sent_at", "banned_until"))

	phoneFactor := models.NewPhoneFactor(user, "111222333", "phone")
	phoneFactor.Status = models.FactorStateVerified.String()
	require.NoError(ts.T(), ts.API.db.Create(phoneFactor))
	totpFactor := models.NewTOTPFactor(user, "totp")
	totpFactor.Status = models.FactorStateVerified.String()
	require.NoError(ts.T(), ts.API.db.Create(totpFactor))

	identity, err := models.NewIdentity(user, "github", map[string]interface{}{"sub": "123", "email": "linked@example.org"})
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(identity))

	expectedKeys := []string{
		"id", "aud", "role", "email", "phone", "confirmation_sent_at",
		"app_metadata", "user_metadata", "identities", "created_at",
		"updated_at", "is_anonymous",
	}

	cases := []struct {
		desc          string
		body          map[string]interface{}
		expectedEmail string
		expectedPhone string
	}{
		{
			desc:          "email",
			body:          map[string]interface{}{"email": "repeat@example.com", "password": "test123"},
			expectedEmail: "repeat@example.com",
		},
		{
			desc:          "email of a linked identity",
			body:          map[string]interface{}{"email": "linked@example.org", "password": "test123"},
			expectedEmail: "linked@example.org",
		},
		{
			desc:          "phone",
			body:          map[string]interface{}{"phone": "123456789", "password": "test123"},
			expectedPhone: "123456789",
		},
	}

	for _, c := range cases {
		ts.Run(c.desc, func() {
			var buffer bytes.Buffer
			require.NoError(ts.T(), json.NewEncoder(&buffer).Encode(c.body))

			req := httptest.NewRequest(http.MethodPost, "http://localhost/signup", &buffer)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			ts.API.handler.ServeHTTP(w, req)
			require.Equal(ts.T(), http.StatusOK, w.Code)

			data := map[string]interface{}{}
			require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))

			keys := make([]string, 0, len(data))
			for k := range data {
				keys = append(keys, k)
			}
			assert.ElementsMatch(ts.T(), expectedKeys, keys)

			assert.NotEqual(ts.T(), user.ID.String(), data["id"])
			assert.Equal(ts.T(), c.expectedEmail, data["email"])
			assert.Equal(ts.T(), c.expectedPhone, data["phone"])
			assert.Empty(ts.T(), data["identities"])
			assert.Equal(ts.T(), map[string]interface{}{}, data["user_metadata"])
		})
	}
}

func (ts *SignupTestSuite) TestVerifySignup() {
	user, err := models.NewUser("123456789", "test@example.com", "testing", ts.Config.JWT.Aud, nil)
	user.ConfirmationToken = "asdf3"
	now := time.Now()
	user.ConfirmationSentAt = &now
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.API.db.Create(user))
	require.NoError(ts.T(), models.CreateOneTimeToken(ts.API.db, user.ID, user.GetEmail(), user.ConfirmationToken, models.ConfirmationToken, ts.Config.Mailer.OtpExpAsDuration(), true))

	// Find test user
	u, err := models.FindUserByEmailAndAudience(ts.API.db, "test@example.com", ts.Config.JWT.Aud)
	require.NoError(ts.T(), err)

	// Setup request
	reqUrl := fmt.Sprintf("http://localhost/verify?type=%s&token=%s", mail.SignupVerification, u.ConfirmationToken)
	req := httptest.NewRequest(http.MethodGet, reqUrl, nil)

	// Setup response recorder
	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)
	assert.Equal(ts.T(), http.StatusSeeOther, w.Code)

	urlVal, err := url.Parse(w.Result().Header.Get("Location"))
	require.NoError(ts.T(), err)
	v, err := url.ParseQuery(urlVal.Fragment)
	require.NoError(ts.T(), err)
	require.NotEmpty(ts.T(), v.Get("access_token"))
	require.NotEmpty(ts.T(), v.Get("expires_in"))
	require.NotEmpty(ts.T(), v.Get("refresh_token"))
}

// TestSignupRequestBodyTooLarge verifies that the MaxBytesReader middleware
// rejects oversized request bodies with a 413 error through the full handler chain.
func (ts *SignupTestSuite) TestSignupRequestBodyTooLarge() {
	// Create a body that exceeds the 1MB limit (1<<20 + 1 bytes)
	largeBody := make([]byte, (1<<20)+1)
	req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	ts.API.handler.ServeHTTP(w, req)

	require.Equal(ts.T(), http.StatusRequestEntityTooLarge, w.Code)

	var data map[string]interface{}
	require.NoError(ts.T(), json.NewDecoder(w.Body).Decode(&data))
	require.Equal(ts.T(), "request_entity_too_large", data["error_code"])
}

type partialConfirmSms struct{ otps []string }

func (p *partialConfirmSms) SendMessage(phone, message, channel, otp string) (string, error) {
	p.otps = append(p.otps, otp)
	return "", nil
}

func (p *partialConfirmSms) VerifyOTP(phone, otp string) error { return nil }

type partialConfirmEnv struct {
	t      *testing.T
	api    *API
	config *conf.GlobalConfiguration
	mailer *mockclient.MockMailer
	sms    *partialConfirmSms
}

const (
	partialConfirmEmail = "partial@example.com"
	partialConfirmPhone = "15550001234"
)

func setupPartialConfirm(t *testing.T) *partialConfirmEnv {
	mailer := &mockclient.MockMailer{}
	api, config, err := setupAPIForTest(WithMailer(mailer))
	require.NoError(t, err)
	t.Cleanup(func() { api.db.Close() })
	config.External.Phone.Enabled = true
	config.Sms.TestOTP = nil
	config.SMTP.MaxFrequency = 0
	config.Sms.MaxFrequency = 0
	sms := &partialConfirmSms{}
	prev := sms_provider.MockProvider
	sms_provider.MockProvider = sms
	t.Cleanup(func() { sms_provider.MockProvider = prev })
	return &partialConfirmEnv{t: t, api: api, config: config, mailer: mailer, sms: sms}
}

func (e *partialConfirmEnv) newUser(t *testing.T, emailConfirmed bool) *models.User {
	db := e.api.db
	require.NoError(t, models.TruncateAll(db))
	e.mailer.Reset()
	e.sms.otps = nil
	e.config.Mailer.Autoconfirm, e.config.Sms.Autoconfirm = false, false

	u, err := models.NewUser(partialConfirmPhone, partialConfirmEmail, "password-1", e.config.JWT.Aud, nil)
	require.NoError(t, err)
	require.NoError(t, db.Create(u))
	if emailConfirmed {
		require.NoError(t, u.Confirm(db))
	} else {
		require.NoError(t, u.ConfirmPhone(db))
	}
	for provider, data := range map[string]map[string]interface{}{
		"email": {"sub": u.ID.String(), "email": partialConfirmEmail},
		"phone": {"sub": u.ID.String(), "phone": partialConfirmPhone},
	} {
		i, err := models.NewIdentity(u, provider, data)
		require.NoError(t, err)
		require.NoError(t, db.Create(i))
	}
	return u
}

func (e *partialConfirmEnv) post(t *testing.T, path string, body map[string]interface{}) (int, map[string]interface{}) {
	var buffer bytes.Buffer
	require.NoError(t, json.NewEncoder(&buffer).Encode(body))
	req := httptest.NewRequest(http.MethodPost, "http://localhost"+path, &buffer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.api.handler.ServeHTTP(w, req)
	data := map[string]interface{}{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&data))
	return w.Code, data
}

func (e *partialConfirmEnv) sessionCount(t *testing.T, user *models.User) int {
	n, err := e.api.db.Q().Where("user_id = ?", user.ID).Count(&models.Session{})
	require.NoError(t, err)
	return n
}

func TestSignupPartiallyConfirmedUser(t *testing.T) {
	e := setupPartialConfirm(t)

	for _, emailConfirmed := range []bool{true, false} {
		for _, mailerAutoconfirm := range []bool{false, true} {
			for _, smsAutoconfirm := range []bool{false, true} {
				desc := fmt.Sprintf("email confirmed %v, mailer autoconfirm %v, sms autoconfirm %v", emailConfirmed, mailerAutoconfirm, smsAutoconfirm)
				t.Run(desc, func(t *testing.T) {
					user := e.newUser(t, emailConfirmed)
					e.config.Mailer.Autoconfirm, e.config.Sms.Autoconfirm = mailerAutoconfirm, smsAutoconfirm
					defer func() { e.config.Mailer.Autoconfirm, e.config.Sms.Autoconfirm = false, false }()

					body := map[string]interface{}{"password": "password-2"}
					if emailConfirmed {
						body["phone"] = partialConfirmPhone
					} else {
						body["email"] = partialConfirmEmail
					}
					code, data := e.post(t, "/signup", body)

					require.Equal(t, http.StatusOK, code)
					require.NotContains(t, data, "access_token")
					require.NotContains(t, data, "refresh_token")
					assert.NotEqual(t, user.ID.String(), data["id"])
					assert.Empty(t, data["identities"])
					if emailConfirmed {
						assert.Empty(t, data["email"])
					} else {
						assert.Empty(t, data["phone"])
					}
					require.Equal(t, 0, e.sessionCount(t, user))

					got, err := models.FindUserByID(e.api.db, user.ID)
					require.NoError(t, err)
					if emailConfirmed {
						assert.Equal(t, smsAutoconfirm, got.IsPhoneConfirmed())
						if smsAutoconfirm {
							assert.Empty(t, e.sms.otps)
						} else {
							assert.Len(t, e.sms.otps, 1)
							assert.NotEmpty(t, got.ConfirmationToken)
						}
					} else {
						assert.Equal(t, mailerAutoconfirm, got.IsConfirmed())
						if mailerAutoconfirm {
							assert.Empty(t, e.mailer.ConfirmationMailCalls)
						} else {
							require.Len(t, e.mailer.ConfirmationMailCalls, 1)
							assert.Equal(t, user.ID, e.mailer.ConfirmationMailCalls[0].User.ID)
							assert.NotEmpty(t, got.ConfirmationToken)
						}
					}

					ok, _, err := got.Authenticate(context.Background(), e.api.db, "password-1", nil, false, "")
					require.NoError(t, err)
					assert.True(t, ok)
					ok, _, err = got.Authenticate(context.Background(), e.api.db, "password-2", nil, false, "")
					require.NoError(t, err)
					assert.False(t, ok)
				})
			}
		}
	}
}

func (e *partialConfirmEnv) newUserMissingIdentity(t *testing.T, emailConfirmed bool) *models.User {
	db := e.api.db
	require.NoError(t, models.TruncateAll(db))
	e.mailer.Reset()
	e.sms.otps = nil
	e.config.Mailer.Autoconfirm, e.config.Sms.Autoconfirm = false, false

	u, err := models.NewUser(partialConfirmPhone, partialConfirmEmail, "password-1", e.config.JWT.Aud, map[string]interface{}{"name": "existing"})
	require.NoError(t, err)
	require.NoError(t, db.Create(u))
	identities := map[string]map[string]interface{}{
		"github": {"sub": "github-1", "email": partialConfirmEmail, "email_verified": false},
	}
	if emailConfirmed {
		require.NoError(t, u.Confirm(db))
		identities["email"] = map[string]interface{}{"sub": u.ID.String(), "email": partialConfirmEmail, "email_verified": true}
	} else {
		require.NoError(t, u.ConfirmPhone(db))
		identities["phone"] = map[string]interface{}{"sub": u.ID.String(), "phone": partialConfirmPhone, "phone_verified": true}
	}
	for provider, data := range identities {
		i, err := models.NewIdentity(u, provider, data)
		require.NoError(t, err)
		require.NoError(t, db.Create(i))
	}
	require.NoError(t, u.UpdateAppMetaDataProviders(db))
	return u
}

type accountSnapshot struct {
	Identities   map[string]string
	IdentityIDs  map[string]string
	UserMetaData map[string]interface{}
	Providers    []interface{}
}

func (e *partialConfirmEnv) snapshot(t *testing.T, user *models.User) accountSnapshot {
	got, err := models.FindUserByID(e.api.db, user.ID)
	require.NoError(t, err)
	s := accountSnapshot{Identities: map[string]string{}, IdentityIDs: map[string]string{}, UserMetaData: map[string]interface{}{}}
	for _, i := range got.Identities {
		data, err := json.Marshal(i.IdentityData)
		require.NoError(t, err)
		s.Identities[i.ID.String()] = i.Provider + " " + string(data)
		s.IdentityIDs[i.ID.String()] = i.Provider
	}
	for k, v := range got.UserMetaData {
		s.UserMetaData[k] = v
	}
	if providers, ok := got.AppMetaData["providers"].([]interface{}); ok {
		s.Providers = providers
	}
	return s
}

func TestPartiallyConfirmedUserMissingIdentity(t *testing.T) {
	e := setupPartialConfirm(t)

	for _, endpoint := range []string{"/signup", "/otp"} {
		for _, emailConfirmed := range []bool{true, false} {
			for _, mailerAutoconfirm := range []bool{false, true} {
				for _, smsAutoconfirm := range []bool{false, true} {
					desc := fmt.Sprintf("%s, email confirmed %v, mailer autoconfirm %v, sms autoconfirm %v", endpoint, emailConfirmed, mailerAutoconfirm, smsAutoconfirm)
					t.Run(desc, func(t *testing.T) {
						user := e.newUserMissingIdentity(t, emailConfirmed)
						before := e.snapshot(t, user)
						e.config.Mailer.Autoconfirm, e.config.Sms.Autoconfirm = mailerAutoconfirm, smsAutoconfirm
						defer func() { e.config.Mailer.Autoconfirm, e.config.Sms.Autoconfirm = false, false }()

						body := map[string]interface{}{"data": map[string]interface{}{"name": "new", "extra": true}}
						if endpoint == "/signup" {
							body["password"] = "password-2"
						}
						if emailConfirmed {
							body["phone"] = partialConfirmPhone
						} else {
							body["email"] = partialConfirmEmail
						}
						code, data := e.post(t, endpoint, body)
						require.Equal(t, http.StatusOK, code, data)
						require.NotContains(t, data, "access_token")
						require.Equal(t, 0, e.sessionCount(t, user))

						after := e.snapshot(t, user)
						assert.Equal(t, before.Identities, after.Identities)
						assert.Equal(t, before.Providers, after.Providers)
						delete(before.UserMetaData, "email_verified")
						delete(after.UserMetaData, "email_verified")
						assert.Equal(t, before.UserMetaData, after.UserMetaData)

						got, err := models.FindUserByID(e.api.db, user.ID)
						require.NoError(t, err)
						// /otp with an email clears an unconfirmed email's password before signup
						if endpoint == "/signup" || emailConfirmed {
							ok, _, err := got.Authenticate(context.Background(), e.api.db, "password-1", nil, false, "")
							require.NoError(t, err)
							assert.True(t, ok)
						}

						var verify map[string]interface{}
						switch {
						case emailConfirmed && len(e.sms.otps) == 1:
							verify = map[string]interface{}{"type": "sms", "phone": partialConfirmPhone, "token": e.sms.otps[0]}
						case !emailConfirmed && len(e.mailer.ConfirmationMailCalls) == 1:
							sent := e.mailer.ConfirmationMailCalls[0].User
							assert.Equal(t, user.ID, sent.ID)
							assert.Equal(t, "existing", sent.UserMetaData["name"])
							assert.NotContains(t, sent.UserMetaData, "extra")
							assert.Len(t, sent.Identities, len(before.Identities))
							verify = map[string]interface{}{"type": "signup", "email": partialConfirmEmail, "token": e.mailer.ConfirmationMailCalls[0].OTP}
						case !emailConfirmed && len(e.mailer.MagicLinkMailCalls) == 1:
							assert.Equal(t, user.ID, e.mailer.MagicLinkMailCalls[0].User.ID)
							verify = map[string]interface{}{"type": "magiclink", "email": partialConfirmEmail, "token": e.mailer.MagicLinkMailCalls[0].OTP}
						}
						autoconfirmed := (emailConfirmed && smsAutoconfirm) || (!emailConfirmed && mailerAutoconfirm)
						if endpoint == "/signup" && autoconfirmed {
							require.Nil(t, verify, "nothing is sent when the identifier is autoconfirmed")
							assert.True(t, got.IsConfirmed())
							assert.True(t, got.IsPhoneConfirmed())
							return
						}
						require.NotNil(t, verify, "a code or link must be sent")
						assert.Equal(t, 1, len(e.sms.otps)+len(e.mailer.ConfirmationMailCalls)+len(e.mailer.MagicLinkMailCalls))

						code, data = e.post(t, "/verify", verify)
						require.Equal(t, http.StatusOK, code, data)
						require.NotEmpty(t, data["access_token"])
						signedIn, ok := data["user"].(map[string]interface{})
						require.True(t, ok)
						assert.Equal(t, user.ID.String(), signedIn["id"])

						got, err = models.FindUserByID(e.api.db, user.ID)
						require.NoError(t, err)
						assert.True(t, got.IsConfirmed())
						assert.True(t, got.IsPhoneConfirmed())
						assert.Equal(t, before.IdentityIDs, e.snapshot(t, user).IdentityIDs)
					})
				}
			}
		}
	}
}
