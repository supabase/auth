package templatemailer

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/observability"
	"golang.org/x/sync/singleflight"
)

func init() {
	// Ensure every TemplateType has a default subject & body.
	if err := checkDefaults(); err != nil {
		panic(err)
	}
}

const (
	maxTemplateSize = 10_000_000
	maxTemplateAge  = time.Second * 10
	maxTemplateIval = maxTemplateAge / 4
)

// Mailer will send mail and use templates from the site for easy mail styling
type Mailer struct {
	cfg *conf.GlobalConfiguration
	tc  *tplCache
	mc  mailer.Client
}

// New will return a *TemplateMailer backed by the given mailer.Client.
func New(globalConfig *conf.GlobalConfiguration, mc mailer.Client) *Mailer {
	return &Mailer{
		cfg: globalConfig,
		tc:  newTplCache(globalConfig),
		mc:  mc,
	}
}

func (m *Mailer) mail(
	ctx context.Context,
	tpl string,
	to string,
	data map[string]any,
) error {
	if _, ok := lookupEmailContentConfig(&m.cfg.Mailer.Subjects, tpl); !ok {
		return fmt.Errorf("templatemailer: template type: %s is invalid", tpl)
	}

	// This is to match the previous behavior, which sent a "reauthenticate"
	// header instead of the same name as template.
	typ := tpl
	if typ == ReauthenticationTemplate {
		typ = "reauthenticate"
	}
	headers := m.Headers(typ)

	ent, err := m.tc.get(ctx, tpl)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	subject, body, err := ent.execute(&buf, data)
	if err != nil {
		return err
	}
	return m.mc.Mail(
		ctx,
		to,
		subject,
		body,
		headers,
		typ,
	)
}

type tplCacheEntry struct {
	createdAt time.Time
	checkedAt time.Time
	typ       string
	subject   *template.Template
	body      *template.Template
}

func newTplCacheEntry(
	at time.Time,
	typ string,
	subject, body *template.Template,
) *tplCacheEntry {
	return &tplCacheEntry{
		createdAt: at,
		checkedAt: at,
		typ:       typ,
		body:      subject,
		subject:   body,
	}
}

func (ent *tplCacheEntry) copy() *tplCacheEntry {
	cpy := *ent
	return &cpy
}

func (ent *tplCacheEntry) execute(
	buf *bytes.Buffer,
	data map[string]any,
) (subject string, body string, err error) {
	if err = ent.subject.Execute(buf, data); err != nil {
		return "", "", err
	}
	subject = buf.String()

	buf.Reset()
	if err = ent.body.Execute(buf, data); err != nil {
		return "", "", err
	}
	body = buf.String()
	return subject, body, nil
}

type tplCache struct {
	cfg *conf.GlobalConfiguration
	sf  singleflight.Group
	now func() time.Time

	maxSize int
	maxAge  time.Duration
	maxIval time.Duration

	// Must hold mu for below field access
	mu sync.Mutex
	m  map[string]*tplCacheEntry
}

func newTplCache(cfg *conf.GlobalConfiguration) *tplCache {
	return &tplCache{
		cfg:     cfg,
		m:       make(map[string]*tplCacheEntry),
		now:     time.Now,
		maxSize: maxTemplateSize,
		maxAge:  maxTemplateAge,
		maxIval: maxTemplateIval,
	}
}

func (o *tplCache) getEntry(typ string) (*tplCacheEntry, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.m[typ]
	return v, ok
}

func (o *tplCache) putEntry(typ string, ent *tplCacheEntry) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.m[typ] = ent
}

// get is the method called to fetch an entry from the cache.
func (o *tplCache) get(
	ctx context.Context,
	typ string,
) (*tplCacheEntry, error) {
	ent, ok := o.getEntry(typ)
	if !ok {
		// Cache miss, straight to load with no current entry.
		return o.load(ctx, typ, nil)
	}

	now := o.now()
	if now.Sub(ent.createdAt) < o.maxAge {
		// Cache hit and the entry is not expired, return it.
		return ent, nil
	}

	// Entry is expired, we check if the entry is ready for reloading. We do
	// as much as we can outside of load to prevent synchronization on o.sf.
	if now.Sub(ent.checkedAt) < o.maxIval {
		// Entry was checked within maxIval, return it.
		return ent, nil
	}

	// Call load with our most recent entry.
	return o.load(ctx, typ, ent)
}

// load is what happens when "get" has a cache miss, the hit has expired or
// the a previously failed check has elapsed the ival.
func (o *tplCache) load(
	ctx context.Context,
	typ string,
	cur *tplCacheEntry,
) (*tplCacheEntry, error) {

	// Before load returns, forget the most recent result of sf. Because we
	// write our cache result in Do we guarantee that the next call to SF
	// after this function returns will be a cache hit.
	defer o.sf.Forget(typ)

	// We prevent a recently restarted auth server from sending multiple
	// concurrent requests to the templating endpoint with pkg singleflight.
	v, err, _ := o.sf.Do(typ, func() (any, error) {

		// First try to load a fresh entry.
		ent, err := o.loadEntry(ctx, typ)
		if err == nil {
			// No error fetching fresh entry, put in cache & return it.
			o.putEntry(typ, ent)
			return ent, nil
		}

		// We had an err loading a fresh entry. Check if we had a current entry
		// and return a copy of that with a last checked time.
		if cur != nil {
			cpy := ent.copy()
			cpy.checkedAt = o.now()

			o.putEntry(typ, cpy)
			return cpy, nil
		}

		// We have no previous entry and no fresh entry, we will load the
		// default templates so the user can continue serving requests.
		//
		// TODO(cstockton): These should be checked more eagerly than a cache hit
		ent = o.loadEntryDefault(typ)
		o.putEntry(typ, ent)
		return ent, nil
	})
	if err != nil {
		// I don't believe SF returns an error unless the fn it calls does, so
		// this is mostly a defensive check.
		err = wrapError(ctx, typ, "internal_error", err)
		return nil, err
	}

	// v is always a *tplCacheEntry
	return v.(*tplCacheEntry), nil
}

// loadEntry returns the
func (o *tplCache) loadEntry(
	ctx context.Context,
	typ string,
) (*tplCacheEntry, error) {
	subjectTemp, err := o.loadEntrySubject(ctx, typ)
	if err != nil {
		return nil, err
	}

	bodyTemp, err := o.loadEntryBody(ctx, typ)
	if err != nil {
		return nil, err
	}

	now := o.now()
	ent := newTplCacheEntry(now, typ, subjectTemp, bodyTemp)
	return ent, nil
}

// loadEntryDefault will never fail due to the checkDefaults() in init().
func (o *tplCache) loadEntryDefault(
	typ string,
) *tplCacheEntry {
	subjectStr := getEmailContentConfig(defaultTemplateSubjects, typ, "")
	subjectTemp := template.Must(template.New("").Parse(subjectStr))

	bodyStr := getEmailContentConfig(defaultTemplateBodies, typ, "")
	bodyTemp := template.Must(template.New("").Parse(bodyStr))

	now := o.now()
	ent := newTplCacheEntry(now, typ, subjectTemp, bodyTemp)
	return ent
}

func (o *tplCache) loadEntrySubject(
	ctx context.Context,
	typ string,
) (*template.Template, error) {

	// This matches the existing behavior, which allow for a potential double
	// parse of the default but it's a minor cost for clean control flow.
	tempStr := getEmailContentConfig(
		&o.cfg.Mailer.Subjects,
		typ,
		getEmailContentConfig(defaultTemplateSubjects, typ, ""))

	temp, err := template.New("Subject").Parse(tempStr)
	if err != nil {
		err = wrapError(ctx, typ, "template_subject_parse_error", err)
		return nil, err
	}
	return temp, nil
}

func (o *tplCache) loadEntryBody(
	ctx context.Context,
	typ string,
) (*template.Template, error) {
	url := getEmailContentConfig(&o.cfg.Mailer.Templates, typ, "")
	if url == "" {

		// We preserve the previous behavior of returning the default.
		tempStr := getEmailContentConfig(defaultTemplateBodies, typ, "")
		temp := template.Must(template.New("").Parse(tempStr))
		return temp, nil
	}
	if !strings.HasPrefix(url, "http") {
		url = o.cfg.SiteURL + url
	}

	tempStr, err := o.fetch(ctx, url)
	if err != nil {
		err = wrapError(ctx, typ, "template_body_http_error", err)
		return nil, err
	}

	temp, err := template.New(url).Parse(tempStr)
	if err != nil {
		err = wrapError(ctx, typ, "template_body_parse_error", err)
		return nil, err
	}
	return temp, nil
}

func (m *tplCache) fetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	rdr := io.LimitReader(res.Body, maxTemplateSize)
	data, err := io.ReadAll(rdr)
	if err != nil {
		return "", err
	}

	body := string(data)
	return body, nil
}

func wrapError(ctx context.Context, typ, label string, err error) error {
	if err == nil {
		return nil
	}

	err = fmt.Errorf(
		"templatemailer: template type %q: %w", typ, err)
	le := observability.GetLogEntryFromContext(ctx).Entry
	le.WithFields(logrus.Fields{
		"event":     "templatemailer_" + label,
		"mail_type": typ,
	}).WithError(err).Error(err)
	return err
}

func lookupEmailContentConfig(
	cfg *conf.EmailContentConfiguration,
	tpl string,
) (string, bool) {
	switch tpl {
	default:
		return "", false
	case InviteTemplate:
		return cfg.Invite, true
	case ConfirmationTemplate:
		return cfg.Confirmation, true
	case RecoveryTemplate:
		return cfg.Recovery, true
	case EmailChangeTemplate:
		return cfg.EmailChange, true
	case ReauthenticationTemplate:
		return cfg.Reauthentication, true
	case MagicLinkTemplate:
		return cfg.MagicLink, true
	}
}

func getEmailContentConfig(
	cfg *conf.EmailContentConfiguration,
	tpl string,
	def string,
) string {
	// This matches behavior of old withDefault ("" != v)
	if v, ok := lookupEmailContentConfig(cfg, tpl); ok && v != "" {
		return v
	}
	return def
}

func checkDefaults() error {
	seen := make(map[string]bool)
	data := map[string]any{
		"ConfirmationURL": "ConfirmationURL",
		"Data":            "Data",
		"Email":           "Email",
		"NewEmail":        "NewEmail",
		"RedirectTo":      "RedirectTo",
		"SendingTo":       "SendingTo",
		"SiteURL":         "SiteURL",
		"Token":           "Token",
		"TokenHash":       "TokenHash",
	}

	buf := new(bytes.Buffer)
	check := func(cfg *conf.EmailContentConfiguration, typ string) error {
		defer buf.Reset()

		tempStr, ok := lookupEmailContentConfig(cfg, typ)
		if !ok {
			return fmt.Errorf(
				"templatemailer: template type %q: missing default body template", typ)
		}

		temp, err := template.New(typ).Parse(tempStr)
		if err != nil {
			return err
		}

		if err := temp.Execute(buf, data); err != nil {
			return err
		}
		return nil
	}

	for _, typ := range templateTypes {
		if seen[typ] {
			return fmt.Errorf(
				"templatemailer: template type %q: duplicate found", typ)
		}
		seen[typ] = true

		if err := check(defaultTemplateSubjects, typ); err != nil {
			return err
		}
		if err := check(defaultTemplateBodies, typ); err != nil {
			return err
		}
	}
	return nil
}
