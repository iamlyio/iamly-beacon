package collector

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestGitHubDeployKeysReturnsOnlyNonSecretInventory(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/orgs/acme/repos":
			return jsonResponse(http.StatusOK, `[{"name":"api","full_name":"acme/api"},{"name":"web","full_name":"acme/web"}]`), nil
		case "/repos/acme/api/keys":
			return jsonResponse(http.StatusOK, `[{"id":42,"title":"production deploy","key":"ssh-ed25519 SECRET-PUBLIC-MATERIAL","read_only":false,"created_at":"2024-01-02T03:04:05Z","last_used":"2026-08-12T10:00:00Z","enabled":true,"added_by":"octocat"}]`), nil
		case "/repos/acme/web/keys":
			return jsonResponse(http.StatusOK, `[]`), nil
		default:
			t.Fatalf("unexpected GitHub path %s", request.URL.Path)
			return nil, nil
		}
	})}

	credentials, coverage := GitHubDeployKeys(context.Background(), map[string]string{"token": "secret-token", "org": "acme"})
	if coverage.Status != "complete" || coverage.ResourcesScanned != 2 || coverage.ResourcesTotal != 2 {
		t.Fatalf("coverage = %#v", coverage)
	}
	if len(credentials) != 1 {
		t.Fatalf("credentials = %#v", credentials)
	}
	got := credentials[0]
	if got.ID != "42" || got.Name != "production deploy" ||
		got.Repository != "acme/api" || got.Access != "write" || got.AddedBy == nil || *got.AddedBy != "octocat" {
		t.Fatalf("credential = %#v", got)
	}
	if strings.Contains(strings.Join([]string{got.ID, got.Name, got.Repository, got.Access}, " "), "SECRET-PUBLIC-MATERIAL") {
		t.Fatal("credential inventory leaked key material")
	}
}

func TestGitHubDeployKeysExcludesDisabledKeys(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/orgs/acme/repos" {
			return jsonResponse(http.StatusOK, `[{"name":"api","full_name":"acme/api"}]`), nil
		}
		return jsonResponse(http.StatusOK, `[{"id":1,"title":"disabled","read_only":true,"enabled":false},{"id":2,"title":"active","read_only":true,"enabled":true}]`), nil
	})}
	credentials, coverage := GitHubDeployKeys(context.Background(), map[string]string{"token": "secret-token", "org": "acme"})
	if coverage.Status != "complete" || len(credentials) != 1 || credentials[0].Name != "active" {
		t.Fatalf("credentials = %#v, coverage = %#v", credentials, coverage)
	}
}

func TestGitHubDeployKeysKeepsAccessibleRepositoriesWhenCoverageIsPartial(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/orgs/acme/repos":
			return jsonResponse(http.StatusOK, `[{"name":"allowed","full_name":"acme/allowed"},{"name":"denied","full_name":"acme/denied"}]`), nil
		case "/repos/acme/allowed/keys":
			return jsonResponse(http.StatusOK, `[{"id":7,"title":"readonly","read_only":true}]`), nil
		case "/repos/acme/denied/keys":
			return jsonResponse(http.StatusForbidden, `{"message":"forbidden"}`), nil
		default:
			t.Fatalf("unexpected GitHub path %s", request.URL.Path)
			return nil, nil
		}
	})}

	credentials, coverage := GitHubDeployKeys(context.Background(), map[string]string{"token": "secret-token", "org": "acme"})
	if len(credentials) != 1 || credentials[0].Access != "read" {
		t.Fatalf("credentials = %#v", credentials)
	}
	if coverage.Status != "partial" || coverage.ResourcesScanned != 1 || coverage.ResourcesTotal != 2 || coverage.Message == nil {
		t.Fatalf("coverage = %#v", coverage)
	}
}

func TestGitHubBillingSpendNormalizesCurrentMonthNetUsage(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/organizations/acme/settings/billing/usage/summary" {
			t.Fatalf("unexpected GitHub path %s", request.URL.Path)
		}
		return jsonResponse(http.StatusOK, `{"usageItems":[{"grossAmount":12,"discountAmount":2,"netAmount":10},{"netAmount":0.123456}]}`), nil
	})}

	spend := githubBillingSpend(context.Background(), "secret-token", "acme")
	if spend == nil || spend.Currency != "USD" || spend.Amount != 10.1235 {
		t.Fatalf("spend = %#v", spend)
	}
}

func TestGitHubBillingFailureDoesNotInventSpend(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusForbidden, `{"message":"billing unavailable"}`), nil
	})}

	if spend := githubBillingSpend(context.Background(), "secret-token", "acme"); spend != nil {
		t.Fatalf("spend = %#v, want nil", spend)
	}
}
