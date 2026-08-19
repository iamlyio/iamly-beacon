package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNPMJSCollectsOrganizationRoster(t *testing.T) {
	originalBase, originalClient := npmRegistryBaseURL, httpClient
	t.Cleanup(func() { npmRegistryBaseURL, httpClient = originalBase, originalClient })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/-/org/acme/user" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer npm-token" || request.Header.Get("Accept") != "application/json" {
			t.Fatalf("unexpected headers %#v", request.Header)
		}
		_, _ = response.Write([]byte(`{"zara":"Developer","ada":"owner"}`))
	}))
	defer server.Close()
	npmRegistryBaseURL, httpClient = server.URL, server.Client()

	members, spend, err := NPMJS(context.Background(), map[string]string{"token": "npm-token", "org": "@acme"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 2 || members[0].Username == nil || *members[0].Username != "ada" || members[0].Role == nil || *members[0].Role != "owner" || members[0].Email != nil {
		t.Fatalf("members=%#v spend=%#v", members, spend)
	}
	if members[1].Username == nil || *members[1].Username != "zara" || members[1].Role == nil || *members[1].Role != "developer" {
		t.Fatalf("second member=%#v", members[1])
	}
}

func TestNPMJSMapsUnauthorizedAndRejectsInvalidJSON(t *testing.T) {
	originalBase, originalClient := npmRegistryBaseURL, httpClient
	t.Cleanup(func() { npmRegistryBaseURL, httpClient = originalBase, originalClient })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	npmRegistryBaseURL, httpClient = server.URL, server.Client()
	_, _, err := NPMJS(context.Background(), map[string]string{"token": "bad", "org": "acme"})
	if err == nil || !strings.Contains(err.Error(), "rejected the local credential") {
		t.Fatalf("credential error=%v", err)
	}

	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`[]`))
	})
	_, _, err = NPMJS(context.Background(), map[string]string{"token": "token", "org": "acme"})
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("invalid JSON error=%v", err)
	}
}
