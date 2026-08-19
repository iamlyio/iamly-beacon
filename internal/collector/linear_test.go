package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLinearCollectsPaginatedUsersAndMapsStatus(t *testing.T) {
	originalURL, originalClient := linearAPIURL, httpClient
	t.Cleanup(func() { linearAPIURL, httpClient = originalURL, originalClient })
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "linear-key" || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected Linear request")
		}
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if json.NewDecoder(request.Body).Decode(&body) != nil ||
			!strings.Contains(body.Query, "users(first: $first, after: $after, includeDisabled: true)") ||
			!strings.Contains(body.Query, "active owner admin guest") {
			t.Fatal("invalid GraphQL request")
		}
		response.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			if body.Variables["after"] != nil {
				t.Fatalf("first after=%v", body.Variables["after"])
			}
			_, _ = response.Write([]byte(`{"data":{"users":{"nodes":[{"id":"u1","name":"Ada","displayName":"ada","email":"ada@example.com","active":true,"owner":true,"admin":true,"createdAt":"2025-01-01T00:00:00Z","lastSeen":"2026-08-01T00:00:00Z"}],"pageInfo":{"hasNextPage":true,"endCursor":"next"}}}}`))
			return
		}
		if body.Variables["after"] != "next" {
			t.Fatalf("second after=%v", body.Variables["after"])
		}
		_, _ = response.Write([]byte(`{"data":{"users":{"nodes":[{"id":"u2","displayName":"visitor","email":"visitor@example.com","active":false,"guest":true}],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`))
	}))
	defer server.Close()
	linearAPIURL, httpClient = server.URL, server.Client()

	members, spend, err := Linear(context.Background(), map[string]string{"apiKey": "linear-key"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || requests != 2 || len(members) != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Role == nil || *members[0].Role != "owner" || members[0].Status != "active" {
		t.Fatalf("owner=%#v", members[0])
	}
	if members[1].Role == nil || *members[1].Role != "guest" || members[1].Status != "deactivated" || members[1].Name == nil || *members[1].Name != "visitor" {
		t.Fatalf("guest=%#v", members[1])
	}
}

func TestLinearRejectsGraphQLErrorsAndRepeatedCursor(t *testing.T) {
	originalURL, originalClient := linearAPIURL, httpClient
	t.Cleanup(func() { linearAPIURL, httpClient = originalURL, originalClient })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"errors":[{"message":"secret detail","extensions":{"code":"AUTHENTICATION_ERROR"}}]}`))
	}))
	defer server.Close()
	linearAPIURL, httpClient = server.URL, server.Client()
	_, _, err := Linear(context.Background(), map[string]string{"apiKey": "key"})
	if err == nil || strings.Contains(err.Error(), "secret detail") || strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("GraphQL error=%v", err)
	}

	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"data":{"users":{"nodes":[],"pageInfo":{"hasNextPage":true,"endCursor":"same"}}}}`))
	})
	_, _, err = Linear(context.Background(), map[string]string{"apiKey": "key"})
	if err != errRepeatedCursor {
		t.Fatalf("cursor error=%v", err)
	}
}
