// Package taskclient provides an implementation of mailer.Client that uses
// the apitask package to send mail in the background.
package taskclient

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/api/apitask"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/mailer"
)

// New will return a Client that runs a task in the background that will later
// call the given Client. If the mailer config EmailBackgroundSending is
// disabled it will return the same Client passed in mc.
func New(globalConfig *conf.GlobalConfiguration, mc mailer.Client) mailer.Client {

	// Check if background emails are enabled
	if globalConfig.Mailer.EmailBackgroundSending {
		mc = &backgroundMailClient{mc: mc}
	}
	return mc
}

// Task holds a mail pending delivery by the Handler.
type Task struct {
	mc mailer.Client

	To      string              `json:"to"`
	Subject string              `json:"subject"`
	Body    string              `json:"body"`
	Headers map[string][]string `json:"headers"`
	Typ     string              `json:"typ"`
}

// Run implements the Type method of the apitask.Task interface by returning
// the "mailer." prefix followed by the mail type.
func (o *Task) Type() string { return fmt.Sprintf("mailer.%v", o.Typ) }

// Run implements the Run method of the apitask.Task interface by attempting
// to send the mail using the underying mail client.
func (o *Task) Run(ctx context.Context) error {
	return o.mc.Mail(
		ctx,
		o.To,
		o.Subject,
		o.Body,
		o.Headers,
		o.Typ)
}

type backgroundMailClient struct {
	mc mailer.Client
	logger logrus.FieldLogger
}

// Mail implements mailer.MailClient interface by sending the call to the
// wrapped mail client to the background. This implementation first tries a
// short synchronous send to detect immediate errors. If that fails it will
// enqueue the task for background retries. If enqueueing fails, it returns an
// error so the caller (HTTP API) does not return success falsely.
func (o *backgroundMailClient) Mail(
	ctx context.Context,
	to string,
	subject string,
	body string,
	headers map[string][]string,
	typ string,
) error {
	// Attempt a short synchronous send first to detect immediate failures.
	shortCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := o.mc.Mail(shortCtx, to, subject, body, headers, typ); err == nil {
		// immediate success
		return nil
	} else {
		// log the sync failure and attempt enqueue
		if o.logger != nil {
			o.logger.WithFields(logrus.Fields{
				"event":     "mail.taskclient.sync_failed",
				"mail_type": typ,
				"mail_to":   to,
			}).WithError(err).Warn("sync mail send failed; attempting enqueue")
		} else {
			logrus.WithFields(logrus.Fields{
				"event":     "mail.taskclient.sync_failed",
				"mail_type": typ,
				"mail_to":   to,
			}).WithError(err).Warn("sync mail send failed; attempting enqueue")
		}
	}

	// Create the task and attempt to enqueue it for background delivery.
	tk := &Task{
		mc:      o.mc,
		To:      to,
		Subject: subject,
		Body:    body,
		Headers: headers,
		Typ:     typ,
	}

	if err := apitask.Run(ctx, tk); err != nil {
		// enqueue failed — return error so API surfaces failure
		if o.logger != nil {
			o.logger.WithFields(logrus.Fields{
				"event":     "mail.taskclient.enqueue_failed",
				"mail_type": typ,
				"mail_to":   to,
			}).WithError(err).Error("enqueue failed")
		} else {
			logrus.WithFields(logrus.Fields{
				"event":     "mail.taskclient.enqueue_failed",
				"mail_type": typ,
				"mail_to":   to,
			}).WithError(err).Error("enqueue failed")
		}
		return fmt.Errorf("taskclient: enqueue failed: %w", err)
	}

	// Enqueued successfully — return nil (background worker will retry/send).
	if o.logger != nil {
		o.logger.WithFields(logrus.Fields{
			"event":     "mail.taskclient.enqueued",
			"mail_type": typ,
			"mail_to":   to,
		}).Info("mail enqueued for background delivery")
	} else {
		logrus.WithFields(logrus.Fields{
			"event":     "mail.taskclient.enqueued",
			"mail_type": typ,
			"mail_to":   to,
		}).Info("mail enqueued for background delivery")
	}
	return nil
}
