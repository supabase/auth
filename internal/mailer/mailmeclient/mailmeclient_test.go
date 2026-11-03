package mailmeclient

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// stalledSMTPServer accepts connections and never sends the SMTP greeting.
func stalledSMTPServer(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	})

	return ln.Addr().(*net.TCPAddr).Port
}

func testClient(port int) *Client {
	return &Client{
		From:   "admin@example.com",
		Host:   "127.0.0.1",
		Port:   port,
		Logger: logrus.StandardLogger(),
	}
}

func TestMailReturnsWhenContextIsDone(t *testing.T) {
	c := testClient(stalledSMTPServer(t))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.Mail(ctx, "user@example.com", "subject", "body", nil, "test")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestMailWithDoneContextStillSends(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// The caller does not wait, but the send is still attempted.
	err = testClient(ln.Addr().(*net.TCPAddr).Port).Mail(ctx, "user@example.com", "subject", "body", nil, "test")
	require.ErrorIs(t, err, context.Canceled)

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("the SMTP server was never contacted")
	}
}

func TestMailReturnsSendError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	err = testClient(port).Mail(context.Background(), "user@example.com", "subject", "body", nil, "test")
	require.Error(t, err)
	require.NotErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}
