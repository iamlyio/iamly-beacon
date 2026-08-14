package collector

import (
	"context"
	"net/http"
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
