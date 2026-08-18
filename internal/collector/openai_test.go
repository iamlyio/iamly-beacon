package collector

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestOpenAICollectsPaginatedOrganizationUsers(t *testing.T) {
	requests := 0
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.Host != "api.openai.com" || request.URL.Path != "/v1/organization/users" {
			t.Fatalf("unexpected OpenAI request %s %s%s", request.Method, request.Host, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer admin-secret" || request.Header.Get("Accept") != "application/json" {
			t.Fatal("OpenAI authentication headers are invalid")
		}
		if request.URL.Query().Get("limit") != "100" {
			t.Fatalf("limit=%q", request.URL.Query().Get("limit"))
		}
		response.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			if request.URL.Query().Get("after") != "" {
				t.Fatal("first OpenAI page unexpectedly has a cursor")
			}
			_, _ = response.Write([]byte(`{"data":[{"id":"user_1","name":"Ada Lovelace","email":"ada@example.com","role":"owner","added_at":1711471533}],"last_id":"user_1","has_more":true}`))
			return
		}
		if request.URL.Query().Get("after") != "user_1" {
			t.Fatalf("after=%q", request.URL.Query().Get("after"))
		}
		_, _ = response.Write([]byte(`{"data":[{"id":"user_2","name":"Grace Hopper","email":"grace@example.com","role":"unexpected-role","added_at":0}],"has_more":false}`))
	}))

	members, spend, err := OpenAI(context.Background(), map[string]string{"adminApiKey": "admin-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 2 || requests != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Status != "active" || members[0].Role == nil || *members[0].Role != "owner" ||
		members[0].CreatedAt == nil || *members[0].CreatedAt != "2024-03-26T16:45:33Z" {
		t.Fatalf("first member=%#v", members[0])
	}
	if members[1].Role == nil || *members[1].Role != "member" || members[1].CreatedAt != nil {
		t.Fatalf("second member=%#v", members[1])
	}
}

func TestOpenAIRejectsRepeatedPaginationCursor(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"data":[],"last_id":"same","has_more":true}`))
	}))
	_, _, err := OpenAI(context.Background(), map[string]string{"adminApiKey": "secret"})
	if err != errRepeatedCursor {
		t.Fatalf("error=%v, want repeated cursor", err)
	}
}

func TestOpenAITransportErrorDoesNotLeakCredential(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	secret := "top-secret-admin-key"
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport accidentally included " + secret)
	})}
	_, _, err := OpenAI(context.Background(), map[string]string{"adminApiKey": secret})
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "accidentally") {
		t.Fatalf("unsafe error=%q", err)
	}
}

func TestOpenAIRejectsMoreMembersThanProtocolAccepts(t *testing.T) {
	body := bytes.NewBufferString(`{"data":[`)
	for index := 0; index <= maxCollectedMembers; index++ {
		if index != 0 {
			body.WriteByte(',')
		}
		body.WriteString(`{}`)
	}
	body.WriteString(`],"has_more":false}`)
	payload := body.String()
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(payload))
	}))
	_, _, err := OpenAI(context.Background(), map[string]string{"adminApiKey": "secret"})
	if err != errMemberLimit {
		t.Fatalf("error=%v, want member limit", err)
	}
}

func TestOpenAIRejectsMissingDataEnvelope(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"has_more":false}`))
	}))
	_, _, err := OpenAI(context.Background(), map[string]string{"adminApiKey": "secret"})
	if err == nil || err.Error() != "OpenAI users collection returned invalid JSON" {
		t.Fatalf("error=%v", err)
	}
}
