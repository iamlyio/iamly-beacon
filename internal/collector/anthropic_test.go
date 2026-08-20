package collector

import (
	"context"
	"net/http"
	"testing"
)

func TestAnthropicCollectsPaginatedOrganizationUsers(t *testing.T) {
	requests := 0
	userRequests := 0
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.Host != "api.anthropic.com" {
			t.Fatalf("unexpected Anthropic request %s %s%s", request.Method, request.Host, request.URL.Path)
		}
		if request.Header.Get("x-api-key") != "admin-secret" || request.Header.Get("anthropic-version") != "2023-06-01" {
			t.Fatal("Anthropic authentication headers are invalid")
		}
		if request.URL.Path == "/v1/organizations/cost_report" {
			if request.URL.Query().Get("bucket_width") != "1d" || request.URL.Query().Get("limit") != "31" ||
				request.URL.Query().Get("starting_at") == "" || request.URL.Query().Get("ending_at") == "" {
				t.Fatalf("invalid Anthropic cost query %s", request.URL.RawQuery)
			}
			_, _ = response.Write([]byte(`{"data":[{"results":[{"amount":"123.45","currency":"USD"}]}],"has_more":false}`))
			return
		}
		if request.URL.Path != "/v1/organizations/users" {
			t.Fatalf("unexpected Anthropic path %s", request.URL.Path)
		}
		userRequests++
		if request.URL.Query().Get("limit") != "100" {
			t.Fatalf("limit=%q", request.URL.Query().Get("limit"))
		}
		if userRequests == 1 {
			_, _ = response.Write([]byte(`{"data":[{"id":"user_1","email":"ada@example.com","name":"Ada","role":"developer","added_at":"2026-06-12T09:14:03+02:00"}],"last_id":"user_1","has_more":true}`))
			return
		}
		if request.URL.Query().Get("after_id") != "user_1" {
			t.Fatalf("after_id=%q", request.URL.Query().Get("after_id"))
		}
		_, _ = response.Write([]byte(`{"data":[{"id":"user_2","email":"grace@example.com","name":"Grace","role":"injected role","added_at":"not-a-time"}],"has_more":false}`))
	}))

	members, spend, err := Anthropic(context.Background(), map[string]string{"adminApiKey": "admin-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if spend == nil || spend.Amount != 1.2345 || spend.Currency != "USD" || len(members) != 2 || requests != 3 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Role == nil || *members[0].Role != "developer" || members[0].CreatedAt == nil || *members[0].CreatedAt != "2026-06-12T07:14:03Z" {
		t.Fatalf("first member=%#v", members[0])
	}
	if members[1].Role == nil || *members[1].Role != "member" || members[1].CreatedAt != nil {
		t.Fatalf("second member=%#v", members[1])
	}
}

func TestAnthropicCostFailureDoesNotDiscardMembers(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/organizations/cost_report" {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = response.Write([]byte(`{"data":[{"id":"user_1"}],"has_more":false}`))
	}))
	members, spend, err := Anthropic(context.Background(), map[string]string{"adminApiKey": "secret"})
	if err != nil || len(members) != 1 || spend != nil {
		t.Fatalf("members=%#v spend=%#v err=%v", members, spend, err)
	}
}

func TestAnthropicRejectsMissingPaginationCursor(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"data":[],"has_more":true}`))
	}))
	_, _, err := Anthropic(context.Background(), map[string]string{"adminApiKey": "secret"})
	if err == nil || err.Error() != "Anthropic users collection returned invalid pagination" {
		t.Fatalf("error=%v", err)
	}
}

func TestAnthropicCredentialErrorDoesNotExposeResponseBody(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"error":{"message":"admin-secret leaked here"}}`))
	}))
	_, _, err := Anthropic(context.Background(), map[string]string{"adminApiKey": "admin-secret"})
	if err == nil || err.Error() != "Anthropic rejected the local credential (HTTP 401)" {
		t.Fatalf("error=%v", err)
	}
}

func TestAnthropicRejectsMissingDataEnvelope(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"has_more":false}`))
	}))
	_, _, err := Anthropic(context.Background(), map[string]string{"adminApiKey": "secret"})
	if err == nil || err.Error() != "Anthropic users collection returned invalid JSON" {
		t.Fatalf("error=%v", err)
	}
}
