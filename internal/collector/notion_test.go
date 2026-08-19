package collector

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductivityCollectorTransportErrorsDoNotLeakCredentials(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	secret := "never-print-this-secret"
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport exposed " + secret)
	})}
	cases := []struct {
		name        string
		collector   Collector
		credentials map[string]string
	}{
		{"Notion", Notion, map[string]string{"token": secret}},
		{"Figma", Figma, map[string]string{"token": secret, "tenantId": "tenant"}},
		{"Linear", Linear, map[string]string{"apiKey": secret}},
		{"Vercel", Vercel, map[string]string{"token": secret, "teamId": "team"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := test.collector(context.Background(), test.credentials)
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "exposed") {
				t.Fatalf("unsafe transport error=%v", err)
			}
		})
	}
}

func TestNotionCollectsPaginatedUsers(t *testing.T) {
	originalBase, originalClient := notionAPIBaseURL, httpClient
	t.Cleanup(func() { notionAPIBaseURL, httpClient = originalBase, originalClient })
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/v1/users" ||
			request.Header.Get("Authorization") != "Bearer notion-secret" ||
			request.Header.Get("Notion-Version") != "2026-03-11" ||
			request.URL.Query().Get("page_size") != "100" {
			t.Fatalf("unexpected request: %s %s headers=%v", request.Method, request.URL.String(), request.Header)
		}
		response.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			_, _ = response.Write([]byte(`{"object":"list","results":[{"id":"person-1","name":"Ada","type":"person","person":{"email":"ada@example.com"}}],"has_more":true,"next_cursor":"cursor-2"}`))
			return
		}
		if request.URL.Query().Get("start_cursor") != "cursor-2" {
			t.Fatalf("second cursor=%q", request.URL.Query().Get("start_cursor"))
		}
		_, _ = response.Write([]byte(`{"object":"list","results":[{"id":"bot-1","name":"Automation","type":"bot"}],"has_more":false,"next_cursor":null}`))
	}))
	defer server.Close()
	notionAPIBaseURL, httpClient = server.URL+"/v1", server.Client()

	members, spend, err := Notion(context.Background(), map[string]string{"token": "notion-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || requests != 2 || len(members) != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Email == nil || *members[0].Email != "ada@example.com" || members[0].Status != "active" {
		t.Fatalf("person=%#v", members[0])
	}
	if members[1].Role == nil || *members[1].Role != "bot" || members[1].Email != nil {
		t.Fatalf("bot=%#v", members[1])
	}
}

func TestNotionMapsCredentialStatusAndBoundsResponses(t *testing.T) {
	originalBase, originalClient := notionAPIBaseURL, httpClient
	t.Cleanup(func() { notionAPIBaseURL, httpClient = originalBase, originalClient })
	oversized := false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if oversized {
			_, _ = response.Write([]byte(strings.Repeat("x", (32<<20)+1)))
			return
		}
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(`{"code":"restricted_resource"}`))
	}))
	defer server.Close()
	notionAPIBaseURL, httpClient = server.URL, server.Client()

	_, _, err := Notion(context.Background(), map[string]string{"token": "bad"})
	if err == nil || !strings.Contains(err.Error(), "rejected the local credential") {
		t.Fatalf("credential error=%v", err)
	}

	oversized = true
	_, _, err = Notion(context.Background(), map[string]string{"token": "token"})
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("oversized response error=%v", err)
	}
}
