package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
	"github.com/supabase/auth/internal/storage/test"
)

type panicHookManager struct {
}

func (m *panicHookManager) InvokeHook(tx *storage.Connection, r *http.Request, input any, output any) error {
	panic("must not be called")
}

type RefreshTokenV2Suite struct {
	suite.Suite

	Conn *storage.Connection

	User *models.User
}

func TestRefreshTokenV2(t *testing.T) {
	ts := &RefreshTokenV2Suite{}

	conn, err := test.SetupDBConnection(ts.config())
	require.NoError(t, err)

	ts.Conn = conn
	defer conn.Close()

	suite.Run(t, ts)
}

func (ts *RefreshTokenV2Suite) SetupTest() {
	models.TruncateAll(ts.Conn)
	u, err := models.NewUser("", "test@example.com", "password", "authenticated", nil)
	require.NoError(ts.T(), err)
	require.NoError(ts.T(), ts.Conn.Create(u))

	ts.User = u
}

func (ts *RefreshTokenV2Suite) config() *conf.GlobalConfiguration {
	config, err := conf.LoadGlobal("../../hack/test.env")
	if err != nil {
		panic("failed to load config")
	}

	config.Security.RefreshTokenAlgorithmVersion = 2

	return config
}

func (ts *RefreshTokenV2Suite) TestNormalUse() {
	config := ts.config()
	require.Equal(ts.T(), 2, config.Security.RefreshTokenAlgorithmVersion)

	config.Security.RefreshTokenRotationEnabled = false
	config.Security.RefreshTokenReuseInterval = 1
	config.Security.RefreshTokenAllowReuse = false

	clock := time.Now()

	srv := NewService(config, &panicHookManager{})
	srv.SetTimeFunc(func() time.Time {
		return clock
	})

	req, err := http.NewRequest("POST", "https://example.com/", nil)
	require.NoError(ts.T(), err)

	req = req.WithContext(context.Background())
	responseHeaders := make(http.Header)

	at, err := srv.IssueRefreshToken(
		req,
		responseHeaders,
		ts.Conn,
		ts.User,
		models.PasswordGrant,
		models.GrantParams{},
	)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), at)

	prt, err := crypto.ParseRefreshToken(at.RefreshToken)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), prt)
	require.Equal(ts.T(), int64(0), prt.Counter)

	session, err := models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), session.UserID.String(), ts.User.ID.String())
	require.NotNil(ts.T(), session.RefreshTokenCounter)
	require.NotNil(ts.T(), session.RefreshTokenHmacKey)
	require.Equal(ts.T(), int64(0), *session.RefreshTokenCounter)

	require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
	require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
	require.Equal(ts.T(), "0", responseHeaders.Get("sb-auth-refresh-token-counter"))

	refreshTokenToUse := at.RefreshToken

	// 128 is used here to force multi-byte encoding of the refresh token counter
	for i := 1; i < 128; i += 1 {
		clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)
		responseHeaders := make(http.Header)

		nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
			RefreshToken: refreshTokenToUse,
		})
		require.NoError(ts.T(), err)

		pnrt, err := crypto.ParseRefreshToken(nrt.RefreshToken)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), pnrt)
		require.Equal(ts.T(), pnrt.SessionID.String(), prt.SessionID.String())
		require.Equal(ts.T(), int64(i), pnrt.Counter)

		refreshedSession, err := models.FindSessionByID(ts.Conn, pnrt.SessionID, false)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenCounter)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenHmacKey)
		require.Equal(ts.T(), int64(i), *refreshedSession.RefreshTokenCounter)

		require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
		require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
		require.Equal(ts.T(), strconv.FormatInt(int64(i), 10), responseHeaders.Get("sb-auth-refresh-token-counter"))

		refreshTokenToUse = nrt.RefreshToken
	}
}

func (ts *RefreshTokenV2Suite) TestMaliciousReuse() {
	config := ts.config()
	require.Equal(ts.T(), 2, config.Security.RefreshTokenAlgorithmVersion)

	config.Security.RefreshTokenRotationEnabled = false
	config.Security.RefreshTokenReuseInterval = 1
	config.Security.RefreshTokenAllowReuse = false

	clock := time.Now()

	srv := NewService(config, &panicHookManager{})
	srv.SetTimeFunc(func() time.Time {
		return clock
	})

	req, err := http.NewRequest("POST", "https://example.com/", nil)
	require.NoError(ts.T(), err)
	responseHeaders := make(http.Header)

	req = req.WithContext(context.Background())

	at, err := srv.IssueRefreshToken(
		req,
		responseHeaders,
		ts.Conn,
		ts.User,
		models.PasswordGrant,
		models.GrantParams{},
	)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), at)

	prt, err := crypto.ParseRefreshToken(at.RefreshToken)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), prt)
	require.Equal(ts.T(), int64(0), prt.Counter)

	session, err := models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), session.UserID.String(), ts.User.ID.String())
	require.NotNil(ts.T(), session.RefreshTokenCounter)
	require.NotNil(ts.T(), session.RefreshTokenHmacKey)
	require.Equal(ts.T(), int64(0), *session.RefreshTokenCounter)

	require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
	require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
	require.Equal(ts.T(), "0", responseHeaders.Get("sb-auth-refresh-token-counter"))

	refreshTokenToUse := at.RefreshToken

	refreshTokens := []string{at.RefreshToken}

	// run through a few regular refresh tokens
	for i := 1; i < 4; i += 1 {
		clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)
		responseHeaders := make(http.Header)

		nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
			RefreshToken: refreshTokenToUse,
		})
		require.NoError(ts.T(), err)

		pnrt, err := crypto.ParseRefreshToken(nrt.RefreshToken)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), pnrt)
		require.Equal(ts.T(), pnrt.SessionID.String(), prt.SessionID.String())
		require.Equal(ts.T(), int64(i), pnrt.Counter)

		refreshedSession, err := models.FindSessionByID(ts.Conn, pnrt.SessionID, false)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenCounter)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenHmacKey)
		require.Equal(ts.T(), int64(i), *refreshedSession.RefreshTokenCounter)

		require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
		require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
		require.Equal(ts.T(), strconv.FormatInt(int64(i), 10), responseHeaders.Get("sb-auth-refresh-token-counter"))

		refreshTokenToUse = nrt.RefreshToken
		refreshTokens = append(refreshTokens, nrt.RefreshToken)
	}

	clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)

	// all but the last two must fail refreshing
	for _, refreshToken := range refreshTokens[:len(refreshTokens)-2] {
		responseHeaders := make(http.Header)

		nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
			RefreshToken: refreshToken,
		})
		require.Error(ts.T(), err)
		require.Nil(ts.T(), nrt)
		require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
		require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))

		refreshedSession, err := models.FindSessionByID(ts.Conn, prt.SessionID, false)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenCounter)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenHmacKey)
		require.Equal(ts.T(), int64(len(refreshTokens)-1), *refreshedSession.RefreshTokenCounter)
	}

	// make sure that the last two allow refreshing
	for _, refreshToken := range refreshTokens[len(refreshTokens)-2:] {
		clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)

		responseHeaders := make(http.Header)

		nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
			RefreshToken: refreshToken,
		})
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), nrt)
	}

	session, err = models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), int64(len(refreshTokens)), *session.RefreshTokenCounter)

	// now update service to use rotation, meaning that after the first reuse
	config.Security.RefreshTokenRotationEnabled = true

	srv = NewService(config, &panicHookManager{})
	srv.SetTimeFunc(func() time.Time {
		return clock
	})

	clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)

	responseHeaders = make(http.Header)

	// reuse the first refresh token, causing the session to be completely deleted
	rrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
		RefreshToken: refreshTokens[0],
	})
	require.Error(ts.T(), err)
	require.Nil(ts.T(), rrt)

	deletedSession, err := models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.Error(ts.T(), err)
	require.True(ts.T(), models.IsNotFoundError(err))
	require.Nil(ts.T(), deletedSession)
}

func (ts *RefreshTokenV2Suite) TestConcurrentReuse() {
	config := ts.config()
	require.Equal(ts.T(), 2, config.Security.RefreshTokenAlgorithmVersion)

	config.Security.RefreshTokenRotationEnabled = true
	config.Security.RefreshTokenReuseInterval = 1
	config.Security.RefreshTokenAllowReuse = false

	clock := time.Now()

	srv := NewService(config, &panicHookManager{})
	srv.SetTimeFunc(func() time.Time {
		return clock
	})

	req, err := http.NewRequest("POST", "https://example.com/", nil)
	require.NoError(ts.T(), err)
	responseHeaders := make(http.Header)

	req = req.WithContext(context.Background())

	at, err := srv.IssueRefreshToken(
		req,
		responseHeaders,
		ts.Conn,
		ts.User,
		models.PasswordGrant,
		models.GrantParams{},
	)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), at)

	prt, err := crypto.ParseRefreshToken(at.RefreshToken)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), prt)
	require.Equal(ts.T(), int64(0), prt.Counter)

	session, err := models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), session.UserID.String(), ts.User.ID.String())
	require.NotNil(ts.T(), session.RefreshTokenCounter)
	require.NotNil(ts.T(), session.RefreshTokenHmacKey)
	require.Equal(ts.T(), int64(0), *session.RefreshTokenCounter)

	require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
	require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
	require.Equal(ts.T(), "0", responseHeaders.Get("sb-auth-refresh-token-counter"))

	refreshTokenToUse := at.RefreshToken
	refreshTokens := []string{at.RefreshToken}

	// refresh the token serially a few times, to mimic a more real-world scenario
	for i := 1; i < 4; i += 1 {
		clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)
		responseHeaders := make(http.Header)

		nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
			RefreshToken: refreshTokenToUse,
		})
		require.NoError(ts.T(), err)

		pnrt, err := crypto.ParseRefreshToken(nrt.RefreshToken)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), pnrt)
		require.Equal(ts.T(), pnrt.SessionID.String(), prt.SessionID.String())
		require.Equal(ts.T(), int64(i), pnrt.Counter)

		refreshedSession, err := models.FindSessionByID(ts.Conn, pnrt.SessionID, false)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenCounter)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenHmacKey)
		require.Equal(ts.T(), int64(i), *refreshedSession.RefreshTokenCounter)

		refreshTokenToUse = nrt.RefreshToken
		refreshTokens = append(refreshTokens, nrt.RefreshToken)
	}

	clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)

	var wg sync.WaitGroup

	endTimeChan := make(chan time.Time)
	defer close(endTimeChan)

	// in CI this can cause quite a bit of issues due to the limited number of connections to the database
	concurrency := 20
	wg.Add(concurrency + 2)

	endTimes := make([]time.Time, 0, concurrency+1)

	go func() {
		defer wg.Done()
		endTimes = append(endTimes, time.Now())

		for i := 0; i < concurrency; i += 1 {
			endTimes = append(endTimes, <-endTimeChan)
		}
	}()

	causesChan := make(chan string)
	defer close(causesChan)

	causes := make([]string, 0, concurrency)

	go func() {
		defer wg.Done()

		for i := 0; i < concurrency; i += 1 {
			causes = append(causes, <-causesChan)
		}
	}()

	for i := 0; i < concurrency; i += 1 {
		go func() {
			defer wg.Done()

			responseHeaders := make(http.Header)
			nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
				RefreshToken: refreshTokenToUse,
			})
			endTimeChan <- time.Now()

			require.NoError(ts.T(), err)
			causesChan <- responseHeaders.Get("sb-auth-refresh-token-reuse-cause")

			pnrt, err := crypto.ParseRefreshToken(nrt.RefreshToken)
			require.NoError(ts.T(), err)
			require.NotNil(ts.T(), pnrt)
			require.Equal(ts.T(), pnrt.SessionID.String(), prt.SessionID.String())
			require.Equal(ts.T(), int64(len(refreshTokens)), pnrt.Counter)

			require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
			require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
			require.Equal(ts.T(), strconv.FormatInt(int64(len(refreshTokens)), 10), responseHeaders.Get("sb-auth-refresh-token-counter"))

			refreshedSession, err := models.FindSessionByID(ts.Conn, pnrt.SessionID, false)
			require.NoError(ts.T(), err)
			require.NotNil(ts.T(), refreshedSession.RefreshTokenCounter)
			require.NotNil(ts.T(), refreshedSession.RefreshTokenHmacKey)
			require.Equal(ts.T(), int64(len(refreshTokens)), *refreshedSession.RefreshTokenCounter)
		}()
	}

	wg.Wait()

	// check that the session exists and was not refreshed concurrency times, but only once
	session, err = models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), session.UserID.String(), ts.User.ID.String())
	require.NotNil(ts.T(), session.RefreshTokenCounter)
	require.NotNil(ts.T(), session.RefreshTokenHmacKey)
	require.Equal(ts.T(), int64(len(refreshTokens)), *session.RefreshTokenCounter)

	// ensure that the end times are naturally sorted, indicating an exclusive lock was used
	for i := 1; i < len(endTimes); i += 1 {
		require.True(ts.T(), endTimes[i-1].Before(endTimes[i]))
	}

	// first refresh is OK
	require.Equal(ts.T(), "", causes[0])

	// second refresh is either concurrent-refresh or fail-to-save
	for _, cause := range causes[1:] {
		require.Equal(ts.T(), "concurrent-refresh,fail-to-save", cause)
	}
}

func (ts *RefreshTokenV2Suite) TestFailToSaveReuse() {
	config := ts.config()
	require.Equal(ts.T(), 2, config.Security.RefreshTokenAlgorithmVersion)

	config.Security.RefreshTokenRotationEnabled = false
	config.Security.RefreshTokenReuseInterval = 1

	clock := time.Now()

	srv := NewService(config, &panicHookManager{})
	srv.SetTimeFunc(func() time.Time {
		return clock
	})

	req, err := http.NewRequest("POST", "https://example.com/", nil)
	require.NoError(ts.T(), err)
	responseHeaders := make(http.Header)

	req = req.WithContext(context.Background())

	at, err := srv.IssueRefreshToken(
		req,
		responseHeaders,
		ts.Conn,
		ts.User,
		models.PasswordGrant,
		models.GrantParams{},
	)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), at)

	prt, err := crypto.ParseRefreshToken(at.RefreshToken)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), prt)
	require.Equal(ts.T(), int64(0), prt.Counter)

	session, err := models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), session.UserID.String(), ts.User.ID.String())
	require.NotNil(ts.T(), session.RefreshTokenCounter)
	require.NotNil(ts.T(), session.RefreshTokenHmacKey)
	require.Equal(ts.T(), int64(0), *session.RefreshTokenCounter)

	require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
	require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
	require.Equal(ts.T(), "0", responseHeaders.Get("sb-auth-refresh-token-counter"))

	refreshTokens := []string{at.RefreshToken}

	// a few regular refresh token calls to prime a real world scenario
	for i := 1; i < 4; i += 1 {
		clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)
		responseHeaders := make(http.Header)

		nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
			RefreshToken: refreshTokens[len(refreshTokens)-1],
		})
		require.NoError(ts.T(), err)

		pnrt, err := crypto.ParseRefreshToken(nrt.RefreshToken)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), pnrt)
		require.Equal(ts.T(), pnrt.SessionID.String(), prt.SessionID.String())
		require.Equal(ts.T(), int64(i), pnrt.Counter)

		require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
		require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
		require.Equal(ts.T(), strconv.FormatInt(int64(i), 10), responseHeaders.Get("sb-auth-refresh-token-counter"))
		require.Equal(ts.T(), "", responseHeaders.Get("sb-auth-refresh-token-reuse-cause"))

		refreshedSession, err := models.FindSessionByID(ts.Conn, pnrt.SessionID, false)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenCounter)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenHmacKey)
		require.Equal(ts.T(), int64(i), *refreshedSession.RefreshTokenCounter)

		refreshTokens = append(refreshTokens, nrt.RefreshToken)
	}

	for i := 0; i < 10; i += 1 {
		// ensure refreshes occur outside of the allowed reuse interval
		clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)
		responseHeaders := make(http.Header)

		nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
			RefreshToken: refreshTokens[len(refreshTokens)-2],
		})
		require.NoError(ts.T(), err)

		pnrt, err := crypto.ParseRefreshToken(nrt.RefreshToken)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), pnrt)
		require.Equal(ts.T(), pnrt.SessionID.String(), prt.SessionID.String())

		// key assertion, ensuring the refresh token returned from the "failed to save" scenario is always the currently active refresh token
		require.Equal(ts.T(), int64(len(refreshTokens)-1), pnrt.Counter)

		require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
		require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
		require.Equal(ts.T(), strconv.FormatInt(int64(len(refreshTokens)-1), 10), responseHeaders.Get("sb-auth-refresh-token-counter"))
		require.Equal(ts.T(), "fail-to-save", responseHeaders.Get("sb-auth-refresh-token-reuse-cause"))

		refreshedSession, err := models.FindSessionByID(ts.Conn, pnrt.SessionID, false)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenCounter)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenHmacKey)
		require.Equal(ts.T(), int64(len(refreshTokens)-1), *refreshedSession.RefreshTokenCounter)
	}
}

func (ts *RefreshTokenV2Suite) TestDBEncryption() {
	config := ts.config()
	require.Equal(ts.T(), 2, config.Security.RefreshTokenAlgorithmVersion)

	config.Security.RefreshTokenRotationEnabled = false
	config.Security.RefreshTokenReuseInterval = 1
	config.Security.RefreshTokenAllowReuse = false

	encryptionKeyA := make([]byte, 32)
	encryptionKeyB := make([]byte, 32)

	rand.Read(encryptionKeyA)
	rand.Read(encryptionKeyB)
	config.Security.DBEncryption.Encrypt = true
	config.Security.DBEncryption.DecryptionKeys = map[string]string{
		"A": base64.RawURLEncoding.EncodeToString(encryptionKeyA),
		"B": base64.RawURLEncoding.EncodeToString(encryptionKeyB),
	}
	config.Security.DBEncryption.EncryptionKeyID = "A"
	config.Security.DBEncryption.EncryptionKey = config.Security.DBEncryption.DecryptionKeys[config.Security.DBEncryption.EncryptionKeyID]

	clock := time.Now()

	srv := NewService(config, &panicHookManager{})
	srv.SetTimeFunc(func() time.Time {
		return clock
	})

	req, err := http.NewRequest("POST", "https://example.com/", nil)
	require.NoError(ts.T(), err)

	req = req.WithContext(context.Background())
	responseHeaders := make(http.Header)

	at, err := srv.IssueRefreshToken(
		req,
		responseHeaders,
		ts.Conn,
		ts.User,
		models.PasswordGrant,
		models.GrantParams{},
	)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), at)

	prt, err := crypto.ParseRefreshToken(at.RefreshToken)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), prt)
	require.Equal(ts.T(), int64(0), prt.Counter)

	session, err := models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.NoError(ts.T(), err)
	require.Equal(ts.T(), session.UserID.String(), ts.User.ID.String())
	require.NotNil(ts.T(), session.RefreshTokenCounter)
	require.NotNil(ts.T(), session.RefreshTokenHmacKey)
	require.Equal(ts.T(), int64(0), *session.RefreshTokenCounter)

	// key assertion
	require.True(ts.T(), strings.Contains(*session.RefreshTokenHmacKey, "\"key_id\":\"A\""))

	require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
	require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
	require.Equal(ts.T(), "0", responseHeaders.Get("sb-auth-refresh-token-counter"))

	refreshTokenToUse := at.RefreshToken

	var encryptedStrings []string

	for i := 1; i < 3; i += 1 {
		clock = clock.Add(time.Duration(config.Security.RefreshTokenReuseInterval)*time.Second + time.Duration(100)*time.Millisecond)
		responseHeaders := make(http.Header)

		// switch the encryption key to trigger re-encryption
		if i%2 == 0 {
			config.Security.DBEncryption.EncryptionKeyID = "A"
		} else {
			config.Security.DBEncryption.EncryptionKeyID = "B"
		}
		config.Security.DBEncryption.EncryptionKey = config.Security.DBEncryption.DecryptionKeys[config.Security.DBEncryption.EncryptionKeyID]

		srv := NewService(config, &panicHookManager{})
		srv.SetTimeFunc(func() time.Time {
			return clock
		})

		nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
			RefreshToken: refreshTokenToUse,
		})
		require.NoError(ts.T(), err)

		pnrt, err := crypto.ParseRefreshToken(nrt.RefreshToken)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), pnrt)
		require.Equal(ts.T(), pnrt.SessionID.String(), prt.SessionID.String())
		require.Equal(ts.T(), int64(i), pnrt.Counter)

		refreshedSession, err := models.FindSessionByID(ts.Conn, pnrt.SessionID, false)
		require.NoError(ts.T(), err)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenCounter)
		require.NotNil(ts.T(), refreshedSession.RefreshTokenHmacKey)
		require.Equal(ts.T(), int64(i), *refreshedSession.RefreshTokenCounter)

		require.Equal(ts.T(), session.UserID.String(), responseHeaders.Get("sb-auth-user-id"))
		require.Equal(ts.T(), session.ID.String(), responseHeaders.Get("sb-auth-session-id"))
		require.Equal(ts.T(), strconv.FormatInt(int64(i), 10), responseHeaders.Get("sb-auth-refresh-token-counter"))

		refreshTokenToUse = nrt.RefreshToken
		encryptedStrings = append(encryptedStrings, *refreshedSession.RefreshTokenHmacKey)
	}

	require.Equal(ts.T(), 2, len(encryptedStrings))
	require.NotEqual(ts.T(), encryptedStrings[0], encryptedStrings[1])
	require.True(ts.T(), strings.Contains(encryptedStrings[0], "\"key_id\":\"B\""))
	require.True(ts.T(), strings.Contains(encryptedStrings[1], "\"key_id\":\"A\""))
}

func (ts *RefreshTokenV2Suite) TestInvalidRefreshTokens() {
	config := ts.config()
	require.Equal(ts.T(), 2, config.Security.RefreshTokenAlgorithmVersion)

	config.Security.RefreshTokenRotationEnabled = false
	config.Security.RefreshTokenReuseInterval = 1
	config.Security.RefreshTokenAllowReuse = false

	clock := time.Now()

	srv := NewService(config, &panicHookManager{})
	srv.SetTimeFunc(func() time.Time {
		return clock
	})

	req, err := http.NewRequest("POST", "https://example.com/", nil)
	require.NoError(ts.T(), err)

	req = req.WithContext(context.Background())
	responseHeaders := make(http.Header)

	at, err := srv.IssueRefreshToken(
		req,
		responseHeaders,
		ts.Conn,
		ts.User,
		models.PasswordGrant,
		models.GrantParams{},
	)
	require.NoError(ts.T(), err)
	require.NotNil(ts.T(), at)

	prt, err := crypto.ParseRefreshToken(at.RefreshToken)
	require.NoError(ts.T(), err)

	session, err := models.FindSessionByID(ts.Conn, prt.SessionID, false)
	require.NoError(ts.T(), err)

	key, _, err := session.GetRefreshTokenHmacKey(config.Security.DBEncryption)
	require.NoError(ts.T(), err)

	// tamper with counter
	prt.Counter += 1
	tamperedRefreshToken := prt.Encode(key)

	responseHeaders = make(http.Header)
	nrt, err := srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
		RefreshToken: tamperedRefreshToken,
	})
	require.Error(ts.T(), err)
	require.Nil(ts.T(), nrt)

	require.Equal(ts.T(), prt.SessionID.String(), responseHeaders.Get("sb-auth-session-id"))

	// tamper with signature
	prt.Counter = 0
	tamperedRefreshToken = prt.Encode(make([]byte, 32))

	responseHeaders = make(http.Header)
	nrt, err = srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
		RefreshToken: tamperedRefreshToken,
	})
	require.Error(ts.T(), err)
	require.Nil(ts.T(), nrt)

	require.Equal(ts.T(), "", responseHeaders.Get("sb-auth-session-id"))

	// remove the session
	err = models.LogoutSession(ts.Conn, prt.SessionID)
	require.NoError(ts.T(), err)

	responseHeaders = make(http.Header)
	nrt, err = srv.RefreshTokenGrant(context.Background(), ts.Conn, req, responseHeaders, RefreshTokenGrantParams{
		RefreshToken: at.RefreshToken,
	})
	require.Error(ts.T(), err)
	require.Nil(ts.T(), nrt)

	require.Equal(ts.T(), "", responseHeaders.Get("sb-auth-session-id"))
}
