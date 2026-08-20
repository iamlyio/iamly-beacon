package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudflareCollectsPaginatedAccountMembers(t *testing.T) {
	const accountID = "0123456789abcdef0123456789abcdef"
	originalBase, originalClient := cloudflareAPIBaseURL, httpClient
	t.Cleanup(func() { cloudflareAPIBaseURL, httpClient = originalBase, originalClient })
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.URL.Path != "/accounts/"+accountID+"/members" ||
			request.Header.Get("Authorization") != "Bearer cf-token" || request.URL.Query().Get("per_page") != "50" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		if requests == 1 {
			if request.URL.Query().Get("page") != "1" {
				t.Fatalf("page=%q", request.URL.Query().Get("page"))
			}
			_, _ = response.Write([]byte(`{"success":true,"result":[{"id":"membership-1","status":"accepted","user":{"email":"owner@example.com","first_name":"Ada","last_name":"Lovelace"},"roles":[{"name":"Super Administrator"}]},{"id":"membership-2","email":"invited@example.com","status":"pending","policies":[{"access":"allow","permission_groups":[{"name":"DNS Read"},{"name":"Workers Scripts Write"}]},{"access":"deny","permission_groups":[{"name":"Billing Write"}]}]}],"result_info":{"page":1,"total_count":3}}`))
			return
		}
		if request.URL.Query().Get("page") != "2" {
			t.Fatalf("page=%q", request.URL.Query().Get("page"))
		}
		_, _ = response.Write([]byte(`{"success":true,"result":[{"id":"membership-3","email":"rejected@example.com","status":"rejected"}],"result_info":{"page":2,"total_count":3}}`))
	}))
	defer server.Close()
	cloudflareAPIBaseURL, httpClient = server.URL, server.Client()

	members, spend, err := Cloudflare(context.Background(), map[string]string{"token": "cf-token", "accountId": accountID})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || requests != 2 || len(members) != 3 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Email == nil || *members[0].Email != "owner@example.com" || members[0].Name == nil ||
		*members[0].Name != "Ada Lovelace" || members[0].Role == nil || *members[0].Role != "Super Administrator" ||
		members[0].Status != "active" {
		t.Fatalf("owner=%#v", members[0])
	}
	if members[1].Role == nil || *members[1].Role != "Workers Scripts Write, DNS Read" || members[1].Status != "pending" {
		t.Fatalf("invitation=%#v", members[1])
	}
	if members[2].Status != "deactivated" || members[2].Role == nil || *members[2].Role != "member" {
		t.Fatalf("rejected=%#v", members[2])
	}
}

func TestCloudflareRejectsMissingCredentialsAndBadResponses(t *testing.T) {
	if _, _, err := Cloudflare(context.Background(), map[string]string{"token": "token"}); err == nil || !strings.Contains(err.Error(), "accountId") {
		t.Fatalf("missing credential error=%v", err)
	}
	if _, _, err := Cloudflare(context.Background(), map[string]string{"token": "token", "accountId": "not-an-account"}); err == nil || !strings.Contains(err.Error(), "32 lowercase hexadecimal") {
		t.Fatalf("account ID error=%v", err)
	}

	originalBase, originalClient := cloudflareAPIBaseURL, httpClient
	t.Cleanup(func() { cloudflareAPIBaseURL, httpClient = originalBase, originalClient })
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	cloudflareAPIBaseURL, httpClient = server.URL, server.Client()
	_, _, err := Cloudflare(context.Background(), map[string]string{"token": "bad", "accountId": "0123456789abcdef0123456789abcdef"})
	if err == nil || !strings.Contains(err.Error(), "rejected the local credential") {
		t.Fatalf("credential error=%v", err)
	}

	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"success":true,"result":[],"result_info":{"page":1,"total_count":1}}`))
	})
	_, _, err = Cloudflare(context.Background(), map[string]string{"token": "token", "accountId": "0123456789abcdef0123456789abcdef"})
	if err == nil || !strings.Contains(err.Error(), "pagination metadata") {
		t.Fatalf("pagination error=%v", err)
	}
}
