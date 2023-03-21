package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// ListenAndServe starts the REST API
func (a *API) ListenAndServe(ctx context.Context, hostAndPort string) {
	baseCtx, cancel := context.WithCancel(context.Background())

	log := logrus.WithField("component", "api")

	server := &http.Server{
		Addr:              hostAndPort,
		Handler:           a.handler,
		ReadHeaderTimeout: 2 * time.Second, // to mitigate a Slowloris attack
		BaseContext: func(net.Listener) context.Context {
			return baseCtx
		},
	}

	cleanupWaitGroup.Add(1)
	go func() {
		defer cleanupWaitGroup.Done()

		<-ctx.Done()

		defer cancel() // close baseContext

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Minute)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.WithError(err).Error("shutdown failed")
		}
	}()

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.WithError(err).Fatal("http server listen failed")
	}
}
