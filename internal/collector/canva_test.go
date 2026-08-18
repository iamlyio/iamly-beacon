package collector

import (
	"context"
	"net/http"
	"testing"
)

func TestCanvaCollectsActiveAndDeactivatedSCIMUsers(t *testing.T) {
	requests := 0
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.Host != "www.canva.com" || request.URL.Path != "/_scim/v2/Users" {
			t.Fatalf("unexpected Canva request %s %s%s", request.Method, request.Host, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer canva-secret" || request.Header.Get("Accept") != "application/scim+json" || request.URL.Query().Get("count") != "10" {
			t.Fatal("Canva request authentication or media headers are invalid")
		}
		if requests == 1 {
			if request.URL.Query().Get("startIndex") != "1" {
				t.Fatalf("startIndex=%q", request.URL.Query().Get("startIndex"))
			}
			_, _ = response.Write([]byte(`{"totalResults":2,"startIndex":1,"itemsPerPage":1,"resources":[{"id":"U1","userName":"ada","displayName":"Ada Lovelace","emails":[{"primary":false,"value":"alias@example.com"},{"primary":true,"value":"ada@example.com"}],"active":true,"role":"Admin","meta":{"created":"2024-01-02T03:04:05+02:00"}}]}`))
			return
		}
		if request.URL.Query().Get("startIndex") != "2" {
			t.Fatalf("startIndex=%q", request.URL.Query().Get("startIndex"))
		}
		_, _ = response.Write([]byte(`{"totalResults":2,"startIndex":2,"itemsPerPage":1,"resources":[{"id":"U2","userName":"grace@example.com","displayName":"Grace Hopper","emails":[{"primary":true,"value":"grace@example.com"}],"active":false,"role":"untrusted role","meta":{"created":"invalid"}}]}`))
	}))

	members, spend, err := Canva(context.Background(), map[string]string{"token": "canva-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 2 || requests != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Status != "active" || members[0].Role == nil || *members[0].Role != "brand designer" ||
		members[0].Email == nil || *members[0].Email != "ada@example.com" || members[0].CreatedAt == nil || *members[0].CreatedAt != "2024-01-02T01:04:05Z" {
		t.Fatalf("active user=%#v", members[0])
	}
	if members[1].Status != "deactivated" || members[1].Role == nil || *members[1].Role != "member" || members[1].CreatedAt != nil {
		t.Fatalf("inactive user=%#v", members[1])
	}
}

func TestCanvaRejectsPaginationWithoutProgress(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"totalResults":1,"startIndex":1,"itemsPerPage":0,"resources":[]}`))
	}))
	_, _, err := Canva(context.Background(), map[string]string{"token": "secret"})
	if err == nil || err.Error() != "Canva users collection returned invalid pagination" {
		t.Fatalf("error=%v", err)
	}
}

func TestCanvaCredentialFailureDoesNotExposeResponseBody(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(`{"detail":"secret token and tenant internals"}`))
	}))
	_, _, err := Canva(context.Background(), map[string]string{"token": "secret"})
	if err == nil || err.Error() != "Canva rejected the local credential (HTTP 403)" {
		t.Fatalf("error=%v", err)
	}
}

func TestCanvaRejectsMissingResourcesEnvelope(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"totalResults":0,"startIndex":1,"itemsPerPage":0}`))
	}))
	_, _, err := Canva(context.Background(), map[string]string{"token": "secret"})
	if err == nil || err.Error() != "Canva users collection returned invalid JSON" {
		t.Fatalf("error=%v", err)
	}
}
