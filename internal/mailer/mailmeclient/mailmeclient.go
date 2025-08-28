// Package mailmeclient provides an implementation of mailer.Client that uses
// gopkg.in/gomail.v2 to send via SMTP.
package mailmeclient

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gopkg.in/gomail.v2"

	"github.com/sirupsen/logrus"
	"github.com/supabase/auth/internal/conf"
)

// templateRetries is the amount of time MailMe will try to fetch a URL before giving up
const templateRetries = 3

// templateExpiration is the time period that the template will be cached for
const templateExpiration = 10 * time.Second

// Client lets MailMe send templated mails
type Client struct {
	From        string
	Host        string
	Port        int
	User        string
	Pass        string
	BaseURL     string
	LocalName   string
	FuncMap     template.FuncMap
	Logger      logrus.FieldLogger
	MailLogging bool

	cache *templateCache
}

// New returns a new *Mailer based on the given configuration.
func New(globalConfig *conf.GlobalConfiguration) *Client {
	from := globalConfig.SMTP.FromAddress()
	u, _ := url.ParseRequestURI(globalConfig.API.ExternalURL)
	return &Client{
		Host:        globalConfig.SMTP.Host,
		Port:        globalConfig.SMTP.Port,
		User:        globalConfig.SMTP.User,
		Pass:        globalConfig.SMTP.Pass,
		LocalName:   u.Hostname(),
		From:        from,
		BaseURL:     globalConfig.SiteURL,
		Logger:      logrus.StandardLogger(),
		MailLogging: globalConfig.SMTP.LoggingEnabled,
	}
}

// Mail sends a templated mail. It will try to load the template from a URL, and
// otherwise fall back to the default
func (m *Client) Mail(
	ctx context.Context,
	to, subjectTemplate, templateURL, defaultTemplate string,
	templateData map[string]any,
	headers map[string][]string,
	typ string,
) error {
	if m.FuncMap == nil {
		m.FuncMap = map[string]any{}
	}
	if m.cache == nil {
		m.cache = &templateCache{
			templates: map[string]*mailTemplate{},
			funcMap:   m.FuncMap,
			logger:    m.Logger,
		}
	}

	tmp, err := template.New("Subject").Funcs(template.FuncMap(m.FuncMap)).Parse(subjectTemplate)
	if err != nil {
		return err
	}

	subject := &bytes.Buffer{}
	err = tmp.Execute(subject, templateData)
	if err != nil {
		return err
	}

	body, err := m.mailBody(templateURL, defaultTemplate, templateData)
	if err != nil {
		return err
	}

	mail := gomail.NewMessage()
	mail.SetHeader("From", m.From)
	mail.SetHeader("To", to)
	mail.SetHeader("Subject", subject.String())

	for k, v := range headers {
		if v != nil {
			mail.SetHeader(k, v...)
		}
	}

	mail.SetBody("text/html", body)

	dial := gomail.NewDialer(m.Host, m.Port, m.User, m.Pass)
	if m.LocalName != "" {
		dial.LocalName = m.LocalName
	}

	if m.MailLogging {
		defer func() {
			fields := logrus.Fields{
				"event":     "mail.send",
				"mail_type": typ,
				"mail_from": m.From,
				"mail_to":   to,
			}
			m.Logger.WithFields(fields).Info("mail.send")
		}()
	}
	if err := dial.DialAndSend(mail); err != nil {
		return err
	}
	return nil
}

type mailTemplate struct {
	tmp       *template.Template
	expiresAt time.Time
}

type templateCache struct {
	templates map[string]*mailTemplate
	mutex     sync.Mutex
	funcMap   template.FuncMap
	logger    logrus.FieldLogger
}

func (t *templateCache) Get(url string) (*template.Template, error) {
	cached, ok := t.templates[url]
	if ok && (cached.expiresAt.Before(time.Now())) {
		return cached.tmp, nil
	}
	data, err := t.fetchTemplate(url, templateRetries)
	if err != nil {
		return nil, err
	}
	return t.Set(url, data, templateExpiration)
}

func (t *templateCache) Set(key, value string, expirationTime time.Duration) (*template.Template, error) {
	parsed, err := template.New(key).Funcs(t.funcMap).Parse(value)
	if err != nil {
		return nil, err
	}

	cached := &mailTemplate{
		tmp:       parsed,
		expiresAt: time.Now().Add(expirationTime),
	}
	t.mutex.Lock()
	t.templates[key] = cached
	t.mutex.Unlock()
	return parsed, nil
}

func (t *templateCache) fetchTemplate(url string, triesLeft int) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil && triesLeft > 0 {
		return t.fetchTemplate(url, triesLeft-1)
	}
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 { // OK
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil && triesLeft > 0 {
			return t.fetchTemplate(url, triesLeft-1)
		}
		if err != nil {
			return "", err
		}
		return string(bodyBytes), err
	}
	if triesLeft > 0 {
		return t.fetchTemplate(url, triesLeft-1)
	}
	return "", errors.New("mailer: unable to fetch mail template")
}

func (m *Client) mailBody(url string, defaultTemplate string, data map[string]any) (string, error) {
	if m.FuncMap == nil {
		m.FuncMap = map[string]any{}
	}
	if m.cache == nil {
		m.cache = &templateCache{templates: map[string]*mailTemplate{}, funcMap: m.FuncMap}
	}

	var temp *template.Template
	var err error

	if url != "" {
		var absoluteURL string
		if strings.HasPrefix(url, "http") {
			absoluteURL = url
		} else {
			absoluteURL = m.BaseURL + url
		}
		temp, err = m.cache.Get(absoluteURL)
		if err != nil {
			log.Printf("Error loading template from %v: %v\n", url, err)
		}
	}

	if temp == nil {
		cached, ok := m.cache.templates[url]
		if ok {
			temp = cached.tmp
		} else {
			temp, err = m.cache.Set(url, defaultTemplate, 0)
			if err != nil {
				return "", err
			}
		}
	}

	buf := &bytes.Buffer{}
	err = temp.Execute(buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
