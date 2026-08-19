package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFigmaCollectsPaginatedSCIMUsersAndMapsStatus(t *testing.T) {
	originalBase, originalClient := figmaSCIMBaseURL, httpClient
	t.Cleanup(func() { figmaSCIMBaseURL, httpClient = originalBase, originalClient })
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/scim/v2/tenant-1/Users" || request.Header.Get("Authorization") != "Bearer figma-scim-token" || request.Header.Get("Accept") != "application/scim+json" || request.URL.Query().Get("count") != "3000" {
			t.Fatalf("unexpected request: %s %s headers=%v", request.Method, request.URL.String(), request.Header)
		}
		if requests == 1 {
			if request.URL.Query().Get("startIndex") != "1" {
				t.Fatalf("first startIndex=%q", request.URL.Query().Get("startIndex"))
			}
			_, _ = response.Write([]byte(`{"totalResults":2,"Resources":[{"id":"f1","userName":"admin@example.com","displayName":"Admin","active":true,"emails":[{"value":"alias@example.com"},{"value":"admin@example.com","primary":true}],"roles":[{"type":"seatType","value":"Full"}],"meta":{"created":"2025-01-01T00:00:00Z"},"urn:ietf:params:scim:schemas:extension:figma:enterprise:2.0:User":{"figmaAdmin":true}}]}`))
			return
		}
		if request.URL.Query().Get("startIndex") != "2" {
			t.Fatalf("second startIndex=%q", request.URL.Query().Get("startIndex"))
		}
		_, _ = response.Write([]byte(`{"totalResults":2,"Resources":[{"id":"f2","userName":"former@example.com","displayName":"Former","active":false,"emails":{"value":"former@example.com","primary":"true"},"roles":[{"type":"seatType","value":"Dev"}]}]}`))
	}))
	defer server.Close()
	figmaSCIMBaseURL, httpClient = server.URL+"/scim/v2", server.Client()

	members, spend, err := Figma(context.Background(), map[string]string{"token": "figma-scim-token", "tenantId": "tenant-1"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || requests != 2 || len(members) != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Email == nil || *members[0].Email != "admin@example.com" || members[0].Role == nil || *members[0].Role != "admin" || members[0].Status != "active" {
		t.Fatalf("admin=%#v", members[0])
	}
	if members[1].Role == nil || *members[1].Role != "dev" || members[1].Status != "deactivated" {
		t.Fatalf("former=%#v", members[1])
	}
}

func TestFigmaRequiresTenantAndBoundsPagination(t *testing.T) {
	if _, _, err := Figma(context.Background(), map[string]string{"token": "token"}); err == nil || !strings.Contains(err.Error(), "tenantId") {
		t.Fatalf("missing tenant error=%v", err)
	}
	originalBase, originalClient := figmaSCIMBaseURL, httpClient
	t.Cleanup(func() { figmaSCIMBaseURL, httpClient = originalBase, originalClient })
	tooMany := true
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		if tooMany {
			_, _ = response.Write([]byte(`{"totalResults":100001,"Resources":[]}`))
			return
		}
		_, _ = response.Write([]byte(`{"totalResults":1,"Resources":[]}`))
	}))
	defer server.Close()
	figmaSCIMBaseURL, httpClient = server.URL, server.Client()
	_, _, err := Figma(context.Background(), map[string]string{"token": "token", "tenantId": "tenant"})
	if err != errMemberLimit {
		t.Fatalf("member limit error=%v", err)
	}
	tooMany = false
	_, _, err = Figma(context.Background(), map[string]string{"token": "token", "tenantId": "tenant"})
	if err == nil || !strings.Contains(err.Error(), "pagination metadata") {
		t.Fatalf("bounded pagination error=%v", err)
	}
}
