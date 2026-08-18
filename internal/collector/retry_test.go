package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestVendorRequestRetriesTransientResponsesOnly(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	attempts := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return jsonResponse(http.StatusServiceUnavailable, `{"error":"temporary"}`), nil
		}
		return jsonResponse(http.StatusOK, `{}`), nil
	})}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://vendor.example/users", nil)
	response, err := doVendorRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if attempts != 2 {
		t.Fatalf("attempts=%d, want two", attempts)
	}

	attempts = 0
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		return jsonResponse(http.StatusForbidden, `{"error":"forbidden"}`), nil
	})}
	response, err = doVendorRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if attempts != 1 {
		t.Fatalf("credential failure attempts=%d, want one", attempts)
	}
}

func TestVendorErrorCodesCannotInjectLogsOrFindings(t *testing.T) {
	if got := vendorAPIError("Slack", "invalid_auth").Error(); !strings.Contains(got, "invalid_auth") {
		t.Fatalf("safe machine code was hidden: %q", got)
	}
	unsafe := "invalid_auth\n\x1b[2Jforged"
	if got := vendorAPIError("Slack", unsafe).Error(); strings.Contains(got, "forged") || strings.Contains(got, "\x1b") {
		t.Fatalf("unsafe vendor error escaped sanitization: %q", got)
	}
}

func TestVendorJSONDecoderEnforcesExactSizeAndSingleDocument(t *testing.T) {
	var payload map[string]bool
	if err := decodeVendorJSON(strings.NewReader(`{"ok":true}`), 4, &payload); err == nil {
		t.Fatal("oversized vendor response was accepted")
	}
	if err := decodeVendorJSON(strings.NewReader(`{"ok":true}{"forged":true}`), 64, &payload); err == nil {
		t.Fatal("multiple vendor JSON documents were accepted")
	}
	if err := decodeVendorJSON(strings.NewReader("{\"ok\":true}\n"), 64, &payload); err != nil || !payload["ok"] {
		t.Fatalf("valid vendor response was rejected: payload=%v err=%v", payload, err)
	}
}

func TestVendorRequestNeverForwardsCredentialsThroughRedirects(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	var targetReached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetReached.Store(true)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", target.URL)
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	httpClient = redirect.Client()
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, redirect.URL, nil)
	request.Header.Set("Authorization", "Bearer local-vendor-secret")
	response, err := doVendorRequest(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status=%d, want redirect response", response.StatusCode)
	}
	if targetReached.Load() {
		t.Fatal("vendor redirect target received a credential-bearing request")
	}
}
