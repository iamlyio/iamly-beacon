package collector

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// useVendorTestServer keeps the vendor URL visible to the collector while
// routing its request into a real httptest server. Handlers can inspect Host
// to assert that a collector selected the intended vendor origin.
func useVendorTestServer(t *testing.T, handler http.Handler) {
	t.Helper()
	original := httpClient
	server := httptest.NewServer(handler)
	t.Cleanup(func() {
		httpClient = original
		server.Close()
	})
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := server.Client().Transport
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		clone := request.Clone(request.Context())
		clone.Host = request.URL.Host
		clone.URL.Scheme = target.Scheme
		clone.URL.Host = target.Host
		return transport.RoundTrip(clone)
	})}
}
