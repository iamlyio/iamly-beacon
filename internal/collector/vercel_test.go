package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVercelCollectsPaginatedTeamMembers(t *testing.T) {
	originalBase, originalClient := vercelAPIBaseURL, httpClient
	t.Cleanup(func() { vercelAPIBaseURL, httpClient = originalBase, originalClient })
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/v3/teams/team_123/members" || request.Header.Get("Authorization") != "Bearer vercel-token" || request.URL.Query().Get("limit") != "100" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		if requests == 1 {
			_, _ = response.Write([]byte(`{"members":[{"uid":"u1","email":"owner@example.com","username":"owner","name":"Owner","role":"OWNER","confirmed":true,"createdAt":1704067200000}],"pagination":{"hasNext":true,"next":12345},"emailInviteCodes":[{"id":"invite-1","email":"invited@example.com","role":"VIEWER","createdAt":1704067200000,"expired":false},{"id":"invite-old","email":"expired@example.com","role":"MEMBER","expired":true}]}`))
			return
		}
		if request.URL.Query().Get("until") != "12345" {
			t.Fatalf("until=%q", request.URL.Query().Get("until"))
		}
		_, _ = response.Write([]byte(`{"members":[{"uid":"u2","email":"pending@example.com","role":"MEMBER","confirmed":false}],"pagination":{"hasNext":false},"emailInviteCodes":[{"id":"invite-1","email":"invited@example.com","role":"VIEWER","expired":false}]}`))
	}))
	defer server.Close()
	vercelAPIBaseURL, httpClient = server.URL, server.Client()

	members, spend, err := Vercel(context.Background(), map[string]string{"token": "vercel-token", "teamId": "team_123"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || requests != 2 || len(members) != 3 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Role == nil || *members[0].Role != "owner" || members[0].CreatedAt == nil || *members[0].CreatedAt != "2024-01-01T00:00:00Z" {
		t.Fatalf("owner=%#v", members[0])
	}
	if members[1].Status != "pending" || members[1].Email == nil || *members[1].Email != "invited@example.com" ||
		members[1].Role == nil || *members[1].Role != "viewer" {
		t.Fatalf("invitation=%#v", members[1])
	}
	if members[2].Status != "pending" || members[2].Email == nil || *members[2].Email != "pending@example.com" {
		t.Fatalf("unconfirmed member=%#v", members[2])
	}
}

func TestVercelMapsUnauthorizedAndRejectsInvalidPagination(t *testing.T) {
	originalBase, originalClient := vercelAPIBaseURL, httpClient
	t.Cleanup(func() { vercelAPIBaseURL, httpClient = originalBase, originalClient })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	vercelAPIBaseURL, httpClient = server.URL, server.Client()
	_, _, err := Vercel(context.Background(), map[string]string{"token": "bad", "teamId": "team"})
	if err == nil || !strings.Contains(err.Error(), "rejected the local credential") {
		t.Fatalf("credential error=%v", err)
	}

	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"members":[],"pagination":{"hasNext":true,"next":0}}`))
	})
	_, _, err = Vercel(context.Background(), map[string]string{"token": "token", "teamId": "team"})
	if err == nil || !strings.Contains(err.Error(), "pagination metadata") {
		t.Fatalf("pagination error=%v", err)
	}
}
