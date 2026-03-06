package api

import (
	"testing"
	"text/template"
)

func TestGenerateSMSFromTemplateWithEscapedNewline(t *testing.T) {
	tmpl, err := template.New("").Parse(`Your code is {{ .Code }}\n@app.com #{{ .Code }}`)
	if err != nil {
		t.Fatalf("failed to parse template: %v", err)
	}

	message, err := generateSMSFromTemplate(tmpl, "123456")
	if err != nil {
		t.Fatalf("failed to generate SMS: %v", err)
	}

	expected := "Your code is 123456\n@app.com #123456"
	if message != expected {
		t.Fatalf("expected %q, got %q", expected, message)
	}
}

func TestGenerateSMSFromTemplateWithLiteralNewline(t *testing.T) {
	tmpl, err := template.New("").Parse(`Your code is {{ .Code }}
@app.com #{{ .Code }}`)
	if err != nil {
		t.Fatalf("failed to parse template: %v", err)
	}

	message, err := generateSMSFromTemplate(tmpl, "123456")
	if err != nil {
		t.Fatalf("failed to generate SMS: %v", err)
	}

	expected := "Your code is 123456\n@app.com #123456"
	if message != expected {
		t.Fatalf("expected %q, got %q", expected, message)
	}
}
