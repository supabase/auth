package worker

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/observability"
	"golang.org/x/sync/errgroup"
)

// Task is implemented by objects which may be handled by the worker.
type Task interface {

	// Type return a basic name for a task. It is not expected to be consistent
	// with the underlying type, but it should be low cardinality.
	Type() string
}

// job carries *Task along with a logEntry related to the initiating request
// and a createdAt time used to print the duration the task took to process.
type job struct {
	task      Task
	createdAt time.Time
	logEntry  *logrus.Entry
}

func newJob(ctx context.Context, task Task) *job {
	le := observability.GetLogEntryFromContext(ctx).Entry
	return &job{
		task:      task,
		logEntry:  le,
		createdAt: time.Now(),
	}
}

func (o *job) result(err error) {

	// TODO(cstockton): Carrying the log entry from the request gives the
	// ability to correlate failed tasks with a request. The downside is that
	// the log entry is fairly heavy, as large as the "auth_event" task done
	// at the end of the request. This could have a measurable impact on log
	// volume.
	duration := time.Since(o.createdAt)
	le := o.logEntry.WithFields(logrus.Fields{
		"action":    "worker_task",
		"task_type": o.task.Type(),
		"success":   err == nil,
		"duration":  duration,
	})

	logFn := le.Infof
	if err != nil {
		logFn = le.WithError(err).Errorf
	}
	logFn("worker task complete for: %v", o.task.Type())
}

// Worker is a simple background work for async tasks. It has an internal
// channel jobs are sent to which are later picked up by a 1 or more workers.
type Worker struct {

	// must be held for calls to Work, prevents potential double Work() calls
	// to ensure the max per cpu worker count holds true.
	workMu sync.Mutex

	cfg   *conf.GlobalConfiguration
	log   *logrus.Entry
	jobCh chan *job

	mailerHandler *mailerHandler
}

func New(
	cfg *conf.GlobalConfiguration,
	log *logrus.Entry,
) *Worker {
	wrk := &Worker{
		cfg:   cfg,
		jobCh: make(chan *job),
		log:   log,
	}

	wrk.mailerHandler = newMailerHandler(cfg, wrk)
	return wrk
}

// workerState carries state shared across workers.
type workerState struct {
	eg      *errgroup.Group
	workCtx context.Context
}

// Work starts the worker using the given workCtx for executing jobs. It will
// run until the ctx is finished. The assumption here is that the inbound ctx
// will be tied to the baseCtx used in the api http requests. This is important
// as it ensures no http request will hold down the shutdown process due to the
// worker exiting before the http server.
//
// In short, ctx must:
//
//   - NEVER be done BEFORE the httpSrv is shutdown
//   - ALWAYS be done AFTER the httpSrv is shutdown
func (o *Worker) Work(ctx context.Context) error {
	if ok := o.workMu.TryLock(); !ok {
		return errors.New("multiple calls to Work are invalid")
	}
	defer o.workMu.Unlock()

	eg := new(errgroup.Group)
	ws := &workerState{
		eg:      eg,
		workCtx: ctx,
	}

	workerCount := max(runtime.NumCPU(), 1) * o.cfg.Worker.CountPerCPU
	for i := range workerCount {
		eg.Go(func() error { return o.worker(ws, i+1) })
	}

	started := time.Now()
	o.log.WithFields(logrus.Fields{
		"action": "worker_main_start",
	})

	var err error
	defer func() {
		o.log.WithFields(logrus.Fields{
			"action":   "worker_main_stop",
			"duration": time.Since(started),
		})
	}()

	// Wait for all in-flight jobs to finish. This is bound to
	err = eg.Wait()
	return err
}

// worker selects jobs and calls dispatch until ws.workCtx is done.
func (o *Worker) worker(ws *workerState, workerNum int) error {
	le := o.log.WithField("worker_num", workerNum)
	pfx := fmt.Sprintf("worker #%.04d:", workerNum)

	le.Infof("%v started", pfx)
	defer le.Infof("%v exited", pfx)

	// Pulls job and calls dispatch until the exitCtx is done.
	for {
		select {
		case <-ws.workCtx.Done():
			return nil

		case job := <-o.jobCh:
			le.Infof("%v received task type %v", pfx, job.task.Type())
			o.dispatch(ws, job)
		}
	}
}

func unknownTaskError(task Task) error {
	return fmt.Errorf("worker: unknown implementation of Task: %T", task)
}

// dispatch will send a job to an appropriate handler.
func (o *Worker) dispatch(ws *workerState, job *job) {
	switch task := job.task.(type) {
	case *MailerTask:
		var err error
		defer func() { job.result(err) }()

		err = o.mailerHandler.Handle(ws.workCtx, task)
	default:
		panic(unknownTaskError(task))
	}
}

// Enqueue will attempt to send a task to the internal job queue for up to
// the worker shutdown duration.
func (o *Worker) Enqueue(ctx context.Context, task Task) error {
	ctx, cancel := context.WithTimeout(ctx, o.cfg.Worker.ShutdownDuration)
	defer cancel()

	job := newJob(ctx, task)
	select {
	case o.jobCh <- job:
		return nil
	case <-ctx.Done():

		// If the workCtx becomes done it means the worker shutdown duration
		// was exceed. To prevent blocking the shutdown sequence we attempt
		// for up to 10 seconds to finish work.
		switch task := job.task.(type) {
		case *MailerTask:
			return fmt.Errorf("mail server request timed out")
		default:
			panic(unknownTaskError(task))
		}
	}
}

func (o *Worker) GetMailerFunc() mailer.MailClient { return o.mailerHandler }

// MailerTask holds a mail pending delivery by the mailerHandler.
type MailerTask struct {
	To              string              `json:"to"`
	SubjectTemplate string              `json:"subject_template"`
	TemplateURL     string              `json:"template_url"`
	DefaultTemplate string              `json:"default_template"`
	TemplateData    map[string]any      `json:"template_data"`
	Headers         map[string][]string `json:"headers"`
	Typ             string              `json:"typ"`
}

// Type implements worker.Type by returning the task Typ with a "mailer." pfx.
func (o *MailerTask) Type() string { return fmt.Sprintf("mailer.%v", o.Typ) }

// mailerHandler is the task handler for mailer tasks.
type mailerHandler struct {
	cfg *conf.GlobalConfiguration
	wrk *Worker
}

func newMailerHandler(
	cfg *conf.GlobalConfiguration,
	wrk *Worker,
) *mailerHandler {
	return &mailerHandler{
		cfg: cfg,
		wrk: wrk,
	}
}

// Handle implements worker.Handle for mailer tasks.
func (o *mailerHandler) Handle(ctx context.Context, tk *MailerTask) error {
	mc := mailer.NewMailClient(o.cfg)
	return mc.Mail(
		ctx,
		tk.To,
		tk.SubjectTemplate,
		tk.TemplateURL,
		tk.DefaultTemplate,
		tk.TemplateData,
		tk.Headers,
		tk.Typ)
}

// Mail implements mailer.MailClient interface by creating a background task
// to later be sent using the mailer.MailmeMailer implementation.
func (o *mailerHandler) Mail(
	ctx context.Context,
	to string,
	subjectTemplate string,
	templateURL string,
	defaultTemplate string,
	templateData map[string]any,
	headers map[string][]string,
	typ string,
) error {
	tk := &MailerTask{
		to,
		subjectTemplate,
		templateURL,
		defaultTemplate,
		templateData,
		headers,
		typ,
	}
	return o.wrk.Enqueue(ctx, tk)
}
