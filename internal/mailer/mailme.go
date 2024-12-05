package mailer

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"gopkg.in/gomail.v2"

	"github.com/sirupsen/logrus"
)

// TemplateRetries is the amount of time MailMe will try to fetch a URL before giving up
const TemplateRetries = 3

// TemplateExpiration is the time period that the template will be cached for
const TemplateExpiration = 10 * time.Second

// MailmeMailer lets MailMe send templated mails
type MailmeMailer struct {
	From           string
	Host           string
	Port           int
	User           string
	Pass           string
	BaseURL        string
	LocalName      string
	FuncMap        template.FuncMap
	cache          *TemplateCache
	Logger         logrus.FieldLogger
	MailLogging    bool
	EmailValidator *EmailValidator
}

// Mail sends a templated mail. It will try to load the template from a URL, and
// otherwise fall back to the default
func (m *MailmeMailer) Mail(
	ctx context.Context,
	to, subjectTemplate, templateURL, defaultTemplate string,
	templateData map[string]interface{},
	headers map[string][]string,
	typ string,
) error {
	if m.FuncMap == nil {
		m.FuncMap = map[string]interface{}{}
	}
	if m.cache == nil {
		m.cache = &TemplateCache{
			templates: map[string]*MailTemplate{},
			funcMap:   m.FuncMap,
			logger:    m.Logger,
		}
	}

	if m.EmailValidator != nil {
		if err := m.EmailValidator.Validate(ctx, to); err != nil {
			return err
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

	body, err := m.MailBody(templateURL, defaultTemplate, templateData)
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

type MailTemplate struct {
	tmp       *template.Template
	expiresAt time.Time
}

type TemplateCache struct {
	templates map[string]*MailTemplate
	mutex     sync.Mutex
	funcMap   template.FuncMap
	logger    logrus.FieldLogger
}

func (t *TemplateCache) Get(url string) (*template.Template, error) {
	cached, ok := t.templates[url]
	if ok && (cached.expiresAt.Before(time.Now())) {
		return cached.tmp, nil
	}
	data, err := t.fetchTemplate(url, TemplateRetries)
	if err != nil {
		return nil, err
	}
	return t.Set(url, data, TemplateExpiration)
}

func (t *TemplateCache) Set(key, value string, expirationTime time.Duration) (*template.Template, error) {
	parsed, err := template.New(key).Funcs(t.funcMap).Parse(value)
	if err != nil {
		return nil, err
	}

	cached := &MailTemplate{
		tmp:       parsed,
		expiresAt: time.Now().Add(expirationTime),
	}
	t.mutex.Lock()
	t.templates[key] = cached
	t.mutex.Unlock()
	return parsed, nil
}

func (t *TemplateCache) fetchTemplate(url string, triesLeft int) (string, error) {
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

func (m *MailmeMailer) MailBody(url string, defaultTemplate string, data map[string]interface{}) (string, error) {
	if m.FuncMap == nil {
		m.FuncMap = map[string]interface{}{}
	}
	if m.cache == nil {
		m.cache = &TemplateCache{templates: map[string]*MailTemplate{}, funcMap: m.FuncMap}
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
