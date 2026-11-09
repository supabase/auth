package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

func TestPasswordStrengthChecks(t *testing.T) {
	examples := []struct {
		MinLength          int
		RequiredCharacters []string

		Password  string
		Reasons   []string
		ErrorCode apierrors.ErrorCode
	}{
		{
			MinLength: 6,
			Password:  "12345",
			Reasons: []string{
				"length",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "123",
			Reasons: []string{
				"length",
				"characters",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "a123",
			Reasons: []string{
				"length",
				"characters",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "ab123",
			Reasons: []string{
				"length",
				"characters",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "c123",
			Reasons: []string{
				"length",
				"characters",
			},
		},
		{
			MinLength: 6,
			RequiredCharacters: []string{
				"a",
				"b",
				"c",
			},
			Password: "abc123",
			Reasons:  nil,
		},
		{
			// 3 runes but 9 bytes: must still be too short
			MinLength: 6,
			Password:  "密码短",
			Reasons:   []string{"length"},
		},
		{
			MinLength: 6,
			Password:  "密码密码密码",
			Reasons:   nil,
		},
		{
			MinLength:          6,
			RequiredCharacters: []string{},
			Password:           "zZgXb5gzyCNrV36qwbOSbKVQsVJd28mC1TwRpeB0y6sFNICJyjD6bILKJMsjyKDzBdaY5tmi8zY9BWJYmt3vULLmyafjIDLYjy8qhETu0mS2jj1uQBgSAzJn9Zjm8EFa",
			Reasons:            nil,
			ErrorCode:          apierrors.ErrorCodeValidationFailed,
		},
	}

	for i, example := range examples {
		api := &API{
			config: &conf.GlobalConfiguration{
				Password: conf.PasswordConfiguration{
					MinLength:          example.MinLength,
					RequiredCharacters: conf.PasswordRequiredCharacters(example.RequiredCharacters),
				},
			},
		}

		err := api.checkPasswordStrength(context.Background(), example.Password)

		switch {
		case len(example.Reasons) > 0:
			var e *WeakPasswordError
			require.ErrorAs(t, err, &e, "Example %d should fail password strength checks", i)
			require.Equal(t, example.Reasons, e.Reasons, "Example %d failed with wrong reasons", i)
		case example.ErrorCode != "":
			var e *HTTPError
			require.ErrorAs(t, err, &e, "Example %d should fail validation", i)
			require.Equal(t, example.ErrorCode, e.ErrorCode, "Example %d failed with wrong error code", i)
		default:
			require.NoError(t, err, "Example %d failed with error", i)
		}
	}
}

const (
	testOldPassword = "old-Password-A-1234"
	testNewPassword = "new-Password-B-5678"
)

func TestPasswordSignInConcurrentAdminUpdate(t *testing.T) {
	e := newSignInEnv(t, true)
	u := e.newUser("signin-admin@example.com")

	update, login := e.runConcurrent(u,
		func() signInResp { return e.adminSetPassword(u, testNewPassword) },
		func() signInResp { return e.login(u.GetEmail(), testOldPassword) },
	)
	require.Equal(t, http.StatusOK, update.code, "admin update: %v", update.body)

	e.requireSignInRejected(login)
	e.requirePasswordUpdated(u)
}

func TestPasswordSignInConcurrentUserUpdate(t *testing.T) {
	e := newSignInEnv(t, true)
	u := e.newUser("signin-user@example.com")
	_, token := e.userSession(u)

	update, login := e.runConcurrent(u,
		func() signInResp { return e.userSetPassword(token, testNewPassword) },
		func() signInResp { return e.login(u.GetEmail(), testOldPassword) },
	)
	require.Equal(t, http.StatusOK, update.code, "PUT /user: %v", update.body)

	e.requireSignInRejected(login)
	e.requirePasswordUpdated(u)
}

func TestPasswordSignInConcurrentUpdateSessions(t *testing.T) {
	for _, encrypt := range []bool{false, true} {
		t.Run("encrypt="+strconv.FormatBool(encrypt), func(t *testing.T) {
			e := newSignInEnv(t, encrypt)
			u := e.newUser(fmt.Sprintf("signin-session-%v@example.com", encrypt))
			sessionID, token := e.userSession(u)

			update, login := e.runConcurrent(u,
				func() signInResp { return e.userSetPassword(token, testNewPassword) },
				func() signInResp { return e.login(u.GetEmail(), testOldPassword) },
			)
			require.Equal(t, http.StatusOK, update.code, "PUT /user: %v", update.body)

			require.Zero(t, e.sessionCount(u, &sessionID), "unexpected sessions after password update (sign-in HTTP %d)", login.code)
			e.requireSignInRejected(login)
		})
	}
}

func TestPasswordSignInConcurrentUpdateMFA(t *testing.T) {
	for _, encrypt := range []bool{false, true} {
		t.Run("encrypt="+strconv.FormatBool(encrypt), func(t *testing.T) {
			e := newSignInEnv(t, encrypt)
			u := e.newUser(fmt.Sprintf("signin-mfa-%v@example.com", encrypt))
			f := e.enrollTOTP(u)
			sessionID, token := e.aal2Session(u, f)

			update, login := e.runConcurrent(u,
				func() signInResp { return e.userSetPassword(token, testNewPassword) },
				func() signInResp { return e.login(u.GetEmail(), testOldPassword) },
			)
			require.Equal(t, http.StatusOK, update.code, "PUT /user at AAL2: %v", update.body)

			require.Zero(t, e.sessionCount(u, &sessionID), "unexpected sessions after password update (sign-in HTTP %d)", login.code)
			e.requireSignInRejected(login)
		})
	}
}

func TestPasswordSignInConcurrentReEncrypt(t *testing.T) {
	e := newSignInEnv(t, true)
	u := e.newUser("signin-reencrypt@example.com")

	first, second := e.runConcurrent(u,
		func() signInResp { return e.login(u.GetEmail(), testOldPassword) },
		func() signInResp { return e.login(u.GetEmail(), testOldPassword) },
	)
	require.Equal(t, http.StatusOK, first.code, "first sign-in: %v", first.body)
	require.Equal(t, http.StatusOK, second.code, "second sign-in: %v", second.body)
	require.NotNil(t, crypto.ParseEncryptedString(e.storedHash(u)), "hash should be encrypted after sign-in")
}

func TestPasswordSignInAAL1CannotChangePasswordOrEmail(t *testing.T) {
	e := newSignInEnv(t, false)
	u := e.newUser("signin-aal1@example.com")
	e.enrollTOTP(u)

	login := e.login(u.GetEmail(), testOldPassword)
	require.Equal(t, http.StatusOK, login.code, "sign-in: %v", login.body)
	access, _ := login.body["access_token"].(string)

	pw := e.userSetPassword(access, testNewPassword)
	require.Equal(t, http.StatusUnauthorized, pw.code, "password change: %v", pw.body)
	require.Equal(t, "insufficient_aal", pw.body["error_code"])

	em := e.do(http.MethodPut, "/user", access, map[string]string{"email": "other@example.com"})
	require.Equal(t, http.StatusUnauthorized, em.code, "email change: %v", em.body)
	require.Equal(t, "insufficient_aal", em.body["error_code"])
}

type signInResp struct {
	code int
	body map[string]any
	took time.Duration
}

type signInEnv struct {
	t      *testing.T
	api    *API
	config *conf.GlobalConfiguration
}

func newSignInEnv(t *testing.T, encrypt bool) *signInEnv {
	api, config, err := setupAPIForTest()
	require.NoError(t, err)
	t.Cleanup(func() { _ = api.db.Close() })

	config.External.Email.Enabled = true
	config.Security.DBEncryption.Encrypt = encrypt
	config.Security.UpdatePasswordRequireReauthentication = false
	config.Security.UpdatePasswordRequireCurrentPassword = false
	config.Password.HIBP.Enabled = false
	require.NoError(t, models.TruncateAll(api.db))
	return &signInEnv{t: t, api: api, config: config}
}

func (e *signInEnv) newUser(email string) *models.User {
	u, err := models.NewUser("", email, testOldPassword, e.config.JWT.Aud, nil)
	require.NoError(e.t, err)
	now := time.Now()
	u.EmailConfirmedAt = &now
	require.NoError(e.t, e.api.db.Create(u))
	require.NotNil(e.t, u.EncryptedPassword)
	require.Nil(e.t, crypto.ParseEncryptedString(*u.EncryptedPassword), "hash should start out as plain bcrypt")
	return u
}

func (e *signInEnv) userSession(u *models.User) (uuid.UUID, string) {
	s, err := models.NewSession(u.ID, nil)
	require.NoError(e.t, err)
	require.NoError(e.t, e.api.db.Create(s))
	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := e.api.generateAccessToken(req, e.api.db, u, &s.ID, models.PasswordGrant)
	require.NoError(e.t, err)
	return s.ID, token
}

func (e *signInEnv) adminToken() string {
	claims := &AccessTokenClaims{Role: "supabase_admin"}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(e.config.JWT.Secret))
	require.NoError(e.t, err)
	return token
}

func (e *signInEnv) do(method, path, bearer string, body any) signInResp {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			panic(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	start := time.Now()
	e.api.handler.ServeHTTP(w, req)
	out := signInResp{code: w.Code, took: time.Since(start)}
	_ = json.Unmarshal(w.Body.Bytes(), &out.body)
	return out
}

func (e *signInEnv) login(email, password string) signInResp {
	return e.do(http.MethodPost, "/token?grant_type=password", "", map[string]string{
		"email":    email,
		"password": password,
	})
}

func (e *signInEnv) adminSetPassword(u *models.User, password string) signInResp {
	return e.do(http.MethodPut, "/admin/users/"+u.ID.String(), e.adminToken(), map[string]string{
		"password": password,
	})
}

func (e *signInEnv) userSetPassword(token, password string) signInResp {
	return e.do(http.MethodPut, "/user", token, map[string]string{
		"password": password,
	})
}

func (e *signInEnv) lockUserRow(u *models.User) (pid int, release func()) {
	locked := make(chan struct{})
	done := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- e.api.db.Transaction(func(tx *storage.Connection) error {
			if err := tx.RawQuery("SELECT 1 FROM "+u.TableName()+" WHERE id = ? FOR NO KEY UPDATE", u.ID).Exec(); err != nil {
				return err
			}
			if err := tx.Store.Get(&pid, "SELECT pg_backend_pid()"); err != nil {
				return err
			}
			close(locked)
			<-done
			return nil
		})
	}()
	select {
	case <-locked:
	case err := <-finished:
		e.t.Fatalf("could not lock user row: %v", err)
	}

	var once sync.Once
	var err error
	release = func() {
		once.Do(func() {
			close(done)
			err = <-finished
		})
		require.NoError(e.t, err)
	}
	e.t.Cleanup(func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	})
	return pid, release
}

func (e *signInEnv) waitForLockWaiters(pid, n int) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		var waiting int
		err := e.api.db.Store.Get(&waiting, `
			WITH RECURSIVE queued AS (
				SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
				UNION
				SELECT a.pid FROM pg_stat_activity a JOIN queued q ON q.pid = ANY(pg_blocking_pids(a.pid))
			)
			SELECT count(*) FROM queued`, pid)
		require.NoError(e.t, err)
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %d lock waiters, have %d", n, waiting)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (e *signInEnv) storedHash(u *models.User) string {
	current, err := models.FindUserByID(e.api.db, u.ID)
	require.NoError(e.t, err)
	require.NotNil(e.t, current.EncryptedPassword)
	return *current.EncryptedPassword
}

func (e *signInEnv) sessionCount(u *models.User, except *uuid.UUID) int {
	q := "SELECT count(*) FROM " + (&models.Session{}).TableName() + " WHERE user_id = $1"
	args := []any{u.ID}
	if except != nil {
		q += " AND id != $2"
		args = append(args, *except)
	}
	var n int
	require.NoError(e.t, e.api.db.Store.Get(&n, q, args...))
	return n
}

func (e *signInEnv) runConcurrent(u *models.User, change func() signInResp, login func() signInResp) (changeResp, loginResp signInResp) {
	pid, release := e.lockUserRow(u)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); changeResp = change() }()
	e.waitForLockWaiters(pid, 1)
	go func() { defer wg.Done(); loginResp = login() }()
	e.waitForLockWaiters(pid, 2)

	release()
	wg.Wait()
	return changeResp, loginResp
}

func (e *signInEnv) requireSignInRejected(login signInResp) {
	require.Equal(e.t, http.StatusBadRequest, login.code, "sign-in: %v", login.body)
	require.Equal(e.t, string(apierrors.ErrorCodeInvalidCredentials), login.body["error_code"])
}

func (e *signInEnv) requirePasswordUpdated(u *models.User) {
	t := e.t
	afterNew := e.login(u.GetEmail(), testNewPassword)
	afterOld := e.login(u.GetEmail(), testOldPassword)
	require.Equal(t, http.StatusOK, afterNew.code, "sign-in with new password: %v", afterNew.body)
	require.NotEqual(t, http.StatusOK, afterOld.code, "sign-in with old password succeeded after update")
}

func (e *signInEnv) enrollTOTP(u *models.User) *models.Factor {
	f := models.NewTOTPFactor(u, "test-totp")
	require.NoError(e.t, f.UpdateStatus(e.api.db, models.FactorStateVerified))
	require.NoError(e.t, f.SetSecret("secretkey", e.config.Security.DBEncryption.Encrypt, e.config.Security.DBEncryption.EncryptionKeyID, e.config.Security.DBEncryption.EncryptionKey))
	require.NoError(e.t, e.api.db.Create(f))
	return f
}

func (e *signInEnv) aal2Session(u *models.User, f *models.Factor) (uuid.UUID, string) {
	s, err := models.NewSession(u.ID, &f.ID)
	require.NoError(e.t, err)
	require.NoError(e.t, e.api.db.Create(s))
	require.NoError(e.t, models.AddClaimToSession(e.api.db, s.ID, models.TOTPSignIn))
	require.NoError(e.t, s.UpdateAALAndAssociatedFactor(e.api.db, models.AAL2, &f.ID))
	req, _ := http.NewRequest(http.MethodPost, "/token?grant_type=password", nil)
	token, _, err := e.api.generateAccessToken(req, e.api.db, u, &s.ID, models.TOTPSignIn)
	require.NoError(e.t, err)
	return s.ID, token
}
