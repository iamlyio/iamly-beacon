package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

func TestGitHubKeysPaginatePATsIndependentlyOfDeployPermissions(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	pages := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/orgs/acme/repos":
			return jsonResponse(http.StatusForbidden, `{"message":"secret-token"}`), nil
		case "/orgs/acme/personal-access-tokens":
			pages++
			if request.URL.Query().Get("page") == "1" {
				response := jsonResponse(http.StatusOK, `[{"token_id":31,"token_name":"automation","token_expired":false,"token_expires_at":"2027-01-01T01:00:00+01:00","token_last_used_at":"2026-09-01T01:00:00+01:00","access_granted_at":"2025-01-01T00:00:00Z","owner":{"login":"octocat"},"permissions":{"organization":{"members":"read"},"repository":{"contents":"write"}},"repository_selection":"subset","token":"DO-NOT-UPLOAD"}]`)
				response.Header.Set("Link", `<https://api.github.com/orgs/acme/personal-access-tokens?page=2>; rel="next"`)
				return response, nil
			}
			return jsonResponse(http.StatusOK, `[{"token_id":32,"token_name":"old automation","token_expired":true,"owner":{"login":"other"},"permissions":{},"repository_selection":"all"}]`), nil
		default:
			t.Fatalf("unexpected path: %s", request.URL.Path)
			return nil, nil
		}
	})}
	keys, coverage := CollectKeys(context.Background(), "github", map[string]string{"token": "secret-token", "org": "acme"})
	if pages != 2 || len(keys) != 2 || coverage[0].Status != "unavailable" || coverage[1].Status != "complete" {
		t.Fatalf("pages=%d keys=%#v coverage=%#v", pages, keys, coverage)
	}
	key := keys[0]
	if key.Kind != "api_key" || key.ID != "31" || key.Owner == nil || *key.Owner != "octocat" || key.CreatedAt != nil || key.CreatedBy != nil || key.LastUsedAt == nil || *key.LastUsedAt != "2026-09-01T00:00:00Z" || key.ExpiresAt == nil || *key.ExpiresAt != "2027-01-01T00:00:00Z" || strings.Join(key.Scopes, ",") != "organization:members:read,repository:contents:write" || keys[1].Status != "expired" {
		t.Fatalf("incorrect metadata: %#v", keys)
	}
	encoded, _ := json.Marshal(struct {
		Keys     []protocol.KeyRecord
		Coverage []protocol.KeyCoverage
	}{keys, coverage})
	if strings.Contains(string(encoded), "secret-token") || strings.Contains(string(encoded), "DO-NOT-UPLOAD") {
		t.Fatal("key value or provider error body leaked")
	}
}

func TestGitHubKeysDistinguishEmptyMissingAndRepeatedPages(t *testing.T) {
	for _, fixture := range []struct {
		name, body, status string
		repeat             bool
		count              int
	}{
		{name: "empty", body: `[]`, status: "complete"},
		{name: "null", body: `null`, status: "unavailable"},
		{name: "object", body: `{}`, status: "unavailable"},
		{name: "missing expired state", body: `[{"token_id":1,"token_name":"key"}]`, status: "unavailable"},
		{name: "cycle", body: `[{"token_id":1,"token_name":"key","token_expired":false}]`, status: "partial", repeat: true, count: 1},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			original := httpClient
			t.Cleanup(func() { httpClient = original })
			calls := 0
			httpClient = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				calls++
				response := jsonResponse(http.StatusOK, fixture.body)
				if fixture.repeat {
					response.Header.Set("Link", `<https://api.github.com/?page=1>; rel="next"`)
				}
				return response, nil
			})}
			keys, coverage := githubPATKeys(context.Background(), map[string]string{"token": "secret-token", "org": "acme"})
			if coverage.Status != fixture.status || len(keys) != fixture.count || calls > 2 {
				t.Fatalf("keys=%#v coverage=%#v calls=%d", keys, coverage, calls)
			}
		})
	}
}

func TestGitHubDeployKeysRetainReadPagesOnLaterDenial(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/orgs/acme/repos" {
			return jsonResponse(http.StatusOK, `[{"name":"repo","full_name":"acme/repo"}]`), nil
		}
		if request.URL.Query().Get("page") == "1" {
			response := jsonResponse(http.StatusOK, `[{"id":1,"title":"deploy","read_only":true,"enabled":true,"added_by":"creator","key":"ssh-ed25519 PUBLIC-MATERIAL"}]`)
			response.Header.Set("Link", `<https://api.github.com/ignored?page=2>; rel="next"`)
			return response, nil
		}
		return jsonResponse(http.StatusForbidden, `{"message":"local-secret"}`), nil
	})}
	keys, coverage := githubDeployKeys(context.Background(), map[string]string{"token": "local-secret", "org": "acme"})
	if len(keys) != 1 || coverage.Status != "partial" || coverage.ResourcesScanned != 0 || keys[0].Owner != nil || keys[0].CreatedBy == nil || *keys[0].CreatedBy != "creator" {
		t.Fatalf("keys=%#v coverage=%#v", keys, coverage)
	}
}

func TestKeyInventoryWithholdsSecretsAndOversizedMetadata(t *testing.T) {
	keys := []protocol.KeyRecord{
		{ID: "1", Kind: "api_key", Name: "normal", Resource: "acme", Status: "active"},
		{ID: "2", Kind: "api_key", Name: "copied local-secret", Resource: "acme"},
		{ID: "3", Kind: "api_key", Name: strings.Repeat("a", 501), Resource: "acme"},
		{ID: "1", Kind: "api_key", Name: "duplicate", Resource: "acme"},
		{ID: " \t\n", Kind: "api_key", Resource: "acme"},
		{ID: "4", Kind: "api_key", Resource: "\u2003"},
	}
	coverage := []protocol.KeyCoverage{{Kind: "api_key", Status: "complete", ResourcesScanned: 1, ResourcesTotal: 1}}
	got, coverage := sanitizeKeyInventory(keys, coverage, map[string]string{"token": "local-secret", "org": "acme"})
	if len(got) != 1 || got[0].ID != "1" || got[0].Scopes == nil || coverage[0].Status != "partial" {
		t.Fatalf("keys=%#v coverage=%#v", got, coverage)
	}
}

func TestKeyInventoryPreservesNonblankIdentityText(t *testing.T) {
	key := protocol.KeyRecord{ID: " 1 ", Kind: "api_key", Resource: " acme ", Status: "active"}
	coverage := []protocol.KeyCoverage{{Kind: "api_key", Status: "complete", ResourcesScanned: 1, ResourcesTotal: 1}}
	keys, coverage := sanitizeKeyInventory([]protocol.KeyRecord{key}, coverage, nil)
	if len(keys) != 1 || keys[0].ID != key.ID || keys[0].Resource != key.Resource || coverage[0].Status != "complete" {
		t.Fatalf("nonblank identity changed: keys=%#v coverage=%#v", keys, coverage)
	}
}

func TestKeyCoverageMessageUsesCanonicalCharacterLimit(t *testing.T) {
	for _, length := range []int{500, 501} {
		message := strings.Repeat("界", length)
		coverage := []protocol.KeyCoverage{{Kind: "api_key", Status: "unavailable", Message: &message}}
		_, got := sanitizeKeyInventory(nil, coverage, nil)
		if got[0].Message == nil || got[0].Status != "unavailable" {
			t.Fatalf("coverage lost its failure details: %#v", got)
		}
		if length == 500 && *got[0].Message != message {
			t.Fatal("valid 500-character coverage message was altered")
		}
		if length == 501 && len([]rune(*got[0].Message)) > 500 {
			t.Fatal("oversized coverage message would reject the result upload")
		}
	}
}
