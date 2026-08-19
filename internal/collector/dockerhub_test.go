package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDockerHubAuthenticatesAndCollectsPaginatedMembers(t *testing.T) {
	originalBase, originalClient := dockerHubAPIBaseURL, httpClient
	t.Cleanup(func() { dockerHubAPIBaseURL, httpClient = originalBase, originalClient })
	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v2/auth/token":
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("unexpected auth request %s %#v", request.Method, request.Header)
			}
			var body map[string]string
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["identifier"] != "docker-user" || body["secret"] != "docker-secret" {
				t.Fatalf("auth body=%#v err=%v", body, err)
			}
			_, _ = response.Write([]byte(`{"access_token":"short-lived"}`))
		case "/v2/orgs/acme/members":
			pages++
			if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer short-lived" || request.URL.Query().Get("page_size") != "100" || request.URL.Query().Get("invites") != "true" || request.URL.Query().Get("type") != "all" {
				t.Fatalf("unexpected members request %s %s %#v", request.Method, request.URL.String(), request.Header)
			}
			if pages == 1 {
				_, _ = response.Write([]byte(`{"next":"page-2","results":[{"id":"42","primary_email":"ada@example.com","full_name":"Ada Lovelace","username":"ada","role":"owner","date_joined":"2024-01-01T00:00:00Z","last_seen_at":"2025-02-03T04:05:06Z"}]}`))
				return
			}
			if request.URL.Query().Get("page") != "2" {
				t.Fatalf("page=%q", request.URL.Query().Get("page"))
			}
			_, _ = response.Write([]byte(`[{"next":null,"results":[{"email":"invited@example.com","role":"Invitee"}]}]`))
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()
	dockerHubAPIBaseURL, httpClient = server.URL, server.Client()

	members, spend, err := DockerHub(context.Background(), map[string]string{"identifier": "docker-user", "secret": "docker-secret", "org": "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || pages != 2 || len(members) != 2 {
		t.Fatalf("members=%#v spend=%#v pages=%d", members, spend, pages)
	}
	if members[0].ID == nil || *members[0].ID != "42" || members[0].Email == nil || *members[0].Email != "ada@example.com" || members[0].LastLoginAt == nil || members[0].Status != "active" {
		t.Fatalf("member=%#v", members[0])
	}
	if members[1].Status != "pending" || members[1].ID == nil || *members[1].ID != "invited@example.com" {
		t.Fatalf("invitation=%#v", members[1])
	}
}

func TestDockerHubMapsAuthenticationFailure(t *testing.T) {
	originalBase, originalClient := dockerHubAPIBaseURL, httpClient
	t.Cleanup(func() { dockerHubAPIBaseURL, httpClient = originalBase, originalClient })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"detail":"bad credential"}`))
	}))
	defer server.Close()
	dockerHubAPIBaseURL, httpClient = server.URL, server.Client()
	_, _, err := DockerHub(context.Background(), map[string]string{"identifier": "user", "secret": "bad", "org": "acme"})
	if err == nil || !strings.Contains(err.Error(), "rejected the local credential") {
		t.Fatalf("credential error=%v", err)
	}
}
