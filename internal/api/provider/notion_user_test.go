package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestGetUserDataUsesOwnerFromTokenWhenUsersMeForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/users/me" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		t.Errorf("unexpected path %s", r.URL.Path)
	}))
	defer srv.Close()

	p := notionProvider{APIPath: srv.URL}
	owner := map[string]interface{}{
		"type": "user",
		"user": map[string]interface{}{
			"id":         "notion-user-1",
			"name":       "Notion Test",
			"avatar_url": "http://example.com/avatar",
			"person": map[string]interface{}{
				"email": "notion@example.com",
			},
		},
	}
	tok := (&oauth2.Token{AccessToken: "notion_token"}).WithExtra(map[string]interface{}{
		"owner": owner,
	})

	data, err := p.GetUserData(context.Background(), tok)
	if err != nil {
		t.Fatalf("GetUserData: %v", err)
	}
	if data == nil || len(data.Emails) != 1 || data.Emails[0].Email != "notion@example.com" {
		t.Fatalf("emails: %#v", data)
	}
	if data.Metadata == nil || data.Metadata.Subject != "notion-user-1" || data.Metadata.Name != "Notion Test" {
		t.Fatalf("metadata: %#v", data.Metadata)
	}
}
