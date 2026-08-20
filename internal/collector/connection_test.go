package collector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestConnectionTesterRegistryMatchesSupportedCollectors(t *testing.T) {
	collectors := make([]string, 0, len(Supported))
	testers := make([]string, 0, len(ConnectionTesters))
	for name := range Supported {
		collectors = append(collectors, name)
	}
	for name := range ConnectionTesters {
		testers = append(testers, name)
	}
	sort.Strings(collectors)
	sort.Strings(testers)
	if !reflect.DeepEqual(testers, collectors) {
		t.Fatalf("connection testers = %v, supported collectors = %v", testers, collectors)
	}
}

func TestConnectionProbesUseOneBoundedRead(t *testing.T) {
	tests := []struct {
		name        string
		credentials map[string]string
		path        string
		query       string
		method      string
		body        string
	}{
		{name: "anthropic", credentials: map[string]string{"adminApiKey": "secret"}, path: "/v1/organizations/users", query: "limit=1", method: http.MethodGet, body: `{}`},
		{name: "asana", credentials: map[string]string{"token": "secret", "workspaceGid": "123"}, path: "/api/1.0/users", query: "limit=1", method: http.MethodGet, body: `{}`},
		{name: "bamboohr", credentials: map[string]string{"companyDomain": "acme", "apiKey": strings.Repeat("a", 40)}, path: "/api/v1/employees", query: "page%5Blimit%5D=1", method: http.MethodGet, body: `{}`},
		{name: "canva", credentials: map[string]string{"token": "secret"}, path: "/_scim/v2/Users", query: "count=1", method: http.MethodGet, body: `{}`},
		{name: "cloudflare", credentials: map[string]string{"accountId": strings.Repeat("a", 32), "token": "secret"}, path: "/client/v4/accounts/" + strings.Repeat("a", 32) + "/members", query: "per_page=1", method: http.MethodGet, body: `{"success":true}`},
		{name: "figma", credentials: map[string]string{"tenantId": "tenant", "token": "secret"}, path: "/scim/v2/tenant/Users", query: "count=1", method: http.MethodGet, body: `{}`},
		{name: "github", credentials: map[string]string{"org": "acme", "token": "secret"}, path: "/user/memberships/orgs/acme", query: "", method: http.MethodGet, body: `{}`},
		{name: "linear", credentials: map[string]string{"apiKey": "secret"}, path: "/graphql", query: "", method: http.MethodPost, body: `{"data":{"users":{}}}`},
		{name: "notion", credentials: map[string]string{"token": "secret"}, path: "/v1/users", query: "page_size=1", method: http.MethodGet, body: `{}`},
		{name: "npmjs", credentials: map[string]string{"token": "secret", "org": "acme"}, path: "/-/whoami", query: "", method: http.MethodGet, body: `{"username":"beacon"}`},
		{name: "openai", credentials: map[string]string{"adminApiKey": "secret"}, path: "/v1/organization/users", query: "limit=1", method: http.MethodGet, body: `{}`},
		{name: "slack", credentials: map[string]string{"userToken": "secret"}, path: "/api/users.list", query: "limit=1", method: http.MethodGet, body: `{"ok":true,"members":[]}`},
		{name: "twingate", credentials: map[string]string{"network": "acme", "apiToken": "secret"}, path: "/api/graphql/", query: "", method: http.MethodPost, body: `{"data":{"users":{}}}`},
		{name: "vercel", credentials: map[string]string{"teamId": "team_1", "token": "secret"}, path: "/v3/teams/team_1/members", query: "limit=1", method: http.MethodGet, body: `{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := httpClient
			t.Cleanup(func() { httpClient = original })
			requests := 0
			httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests++
				if request.Method != test.method || request.URL.Path != test.path {
					t.Fatalf("request = %s %s, want %s %s", request.Method, request.URL.Path, test.method, test.path)
				}
				if test.query != "" && !strings.Contains(request.URL.RawQuery, test.query) {
					t.Fatalf("query = %q, want %q", request.URL.RawQuery, test.query)
				}
				if request.Method == http.MethodPost {
					body, _ := io.ReadAll(request.Body)
					if !bytes.Contains(body, []byte("first: 1")) {
						t.Fatalf("GraphQL probe was not bounded: %s", body)
					}
				}
				switch test.name {
				case "anthropic":
					if request.Header.Get("x-api-key") == "" {
						t.Fatal("Anthropic probe omitted authentication")
					}
				case "bamboohr":
					if !strings.HasPrefix(request.Header.Get("Authorization"), "Basic ") {
						t.Fatal("BambooHR probe omitted authentication")
					}
				case "twingate":
					if request.Header.Get("X-API-KEY") == "" {
						t.Fatal("Twingate probe omitted authentication")
					}
				default:
					if request.Header.Get("Authorization") == "" {
						t.Fatalf("%s probe omitted authentication", test.name)
					}
				}
				return jsonResponse(http.StatusOK, test.body), nil
			})}
			if err := TestConnection(context.Background(), test.name, test.credentials); err != nil {
				t.Fatal(err)
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want one bounded request", requests)
			}
		})
	}
}

func TestOAuthConnectionProbesDoNotCollectFullRosters(t *testing.T) {
	googleCredentials := gcpTestCredentials(t)
	googleCredentials["adminEmail"] = "admin@example.com"
	tests := []struct {
		name        string
		credentials map[string]string
		wantReads   int
	}{
		{name: "dockerhub", credentials: map[string]string{"identifier": "beacon", "secret": "secret", "org": "acme"}, wantReads: 1},
		{name: "gcp", credentials: gcpTestCredentials(t), wantReads: 1},
		{name: "google", credentials: googleCredentials, wantReads: 1},
		{name: "tailscale", credentials: map[string]string{"clientId": "client", "clientSecret": "secret"}, wantReads: 0},
		{name: "zoom", credentials: map[string]string{"accountId": "account", "clientId": "client", "clientSecret": "secret"}, wantReads: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := httpClient
			t.Cleanup(func() { httpClient = original })
			reads := 0
			httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodPost && (strings.Contains(request.URL.Path, "token") || request.URL.Host == "oauth2.googleapis.com") {
					if test.name == "tailscale" {
						if err := request.ParseForm(); err != nil || request.Form.Get("scope") != "users:read" {
							t.Fatalf("Tailscale token exchange omitted users:read: %v %v", request.Form, err)
						}
					}
					return jsonResponse(http.StatusOK, `{"access_token":"short-lived"}`), nil
				}
				reads++
				query := request.URL.Query()
				if query.Get("page_size") != "1" && query.Get("pageSize") != "1" && query.Get("maxResults") != "1" {
					t.Fatalf("unbounded read query: %s", request.URL.String())
				}
				if request.Header.Get("Authorization") != "Bearer short-lived" {
					t.Fatalf("roster probe omitted short-lived authorization")
				}
				return jsonResponse(http.StatusOK, `{}`), nil
			})}
			if err := TestConnection(context.Background(), test.name, test.credentials); err != nil {
				t.Fatal(err)
			}
			if reads != test.wantReads {
				t.Fatalf("roster reads = %d, want %d", reads, test.wantReads)
			}
		})
	}
}

func TestConnectionErrorsAreFixedAndSecretSafe(t *testing.T) {
	tests := map[int]ConnectionErrorCode{
		http.StatusBadRequest:         InvalidConfiguration,
		http.StatusUnauthorized:       CredentialsRejected,
		http.StatusForbidden:          PermissionDenied,
		http.StatusTooManyRequests:    RateLimited,
		http.StatusServiceUnavailable: VendorUnavailable,
		http.StatusTeapot:             UnexpectedResponse,
	}
	for status, want := range tests {
		request, _ := http.NewRequest(http.MethodGet, "https://vendor.example/users?token=must-not-leak", nil)
		original := httpClient
		httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(status, `{"error":"must-not-leak"}`), nil
		})}
		err := normalizeConnectionError(context.Background(), probeRequest(context.Background(), "Vendor", request))
		httpClient = original
		if got := ConnectionErrorCodeOf(err); got != want || strings.Contains(err.Error(), "must-not-leak") {
			t.Fatalf("status %d error = %q code = %s, want %s", status, err, got, want)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	original := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	t.Cleanup(func() { httpClient = original })
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://vendor.example", nil)
	err := normalizeConnectionError(ctx, probeRequest(ctx, "Vendor", request))
	if ConnectionErrorCodeOf(err) != TimedOut {
		t.Fatalf("timeout error = %v", err)
	}
}

func TestConnectionTransportFailureIsSanitized(t *testing.T) {
	original := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport included secret-value")
	})}
	t.Cleanup(func() { httpClient = original })
	err := TestConnection(context.Background(), "github", map[string]string{"org": "acme", "token": "secret-value"})
	if ConnectionErrorCodeOf(err) != VendorUnavailable || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("unsafe transport result: %v", err)
	}
}

func TestConnectionRejectsMalformedSuccessfulResponse(t *testing.T) {
	original := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not-json")),
			Header:     make(http.Header),
		}, nil
	})}
	t.Cleanup(func() { httpClient = original })
	err := TestConnection(context.Background(), "github", map[string]string{"org": "acme", "token": "secret"})
	if ConnectionErrorCodeOf(err) != UnexpectedResponse {
		t.Fatalf("malformed response error = %v", err)
	}
}

func TestNPMProbeUsesDocumentedBoundedWhoamiInsteadOfRoster(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/-/whoami" || strings.Contains(request.URL.Path, "/-/org/") {
			t.Fatalf("npm probe requested roster endpoint %s", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"username":"beacon"}`)), Header: make(http.Header)}, nil
	})}
	if err := TestConnection(context.Background(), "npmjs", map[string]string{"token": "secret", "org": "acme"}); err != nil {
		t.Fatal(err)
	}
}
