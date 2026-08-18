package collector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTwingateCollectsUsersAcrossPages(t *testing.T) {
	requests := 0
	useVendorTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.Host != "acme.twingate.com" || request.URL.Path != "/api/graphql/" {
			t.Fatalf("unexpected Twingate endpoint %s %s", request.Method, request.URL.String())
		}
		if request.Header.Get("X-API-KEY") != "api-token" {
			t.Fatal("Twingate API token missing")
		}
		body, _ := io.ReadAll(request.Body)
		var payload struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if json.Unmarshal(body, &payload) != nil || strings.Contains(strings.ToLower(payload.Query), "mutation") {
			t.Fatal("Twingate request was not a read-only GraphQL query")
		}
		if requests == 1 {
			if payload.Variables["after"] != nil {
				t.Fatalf("first cursor=%#v", payload.Variables["after"])
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"data":{"users":{"pageInfo":{"hasNextPage":true,"endCursor":"cursor-2"},"edges":[{"node":{"id":"1","createdAt":"2025-01-02T03:04:05Z","firstName":"Ada","lastName":"Lovelace","email":"ada@example.com","state":"ACTIVE","role":"ADMIN","type":"SYNCED"}}]}}}`))
			return
		}
		if payload.Variables["after"] != "cursor-2" {
			t.Fatalf("second cursor=%#v", payload.Variables["after"])
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"data":{"users":{"pageInfo":{"hasNextPage":false,"endCursor":null},"edges":[{"node":{"id":"2","firstName":"Pending","email":"pending@example.com","state":"PENDING","role":"MEMBER","type":"MANUAL"}},{"node":{"id":"3","email":"off@example.com","state":"DISABLED","role":"SUPPORT","type":"SYNCED"}}]}}}`))
	}))

	members, spend, err := Twingate(context.Background(), map[string]string{"network": "Acme", "apiToken": "api-token"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 3 || requests != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Status != "active" || members[0].Name == nil || *members[0].Name != "Ada Lovelace" || members[0].Role == nil || *members[0].Role != "admin · synced" {
		t.Fatalf("active user=%#v", members[0])
	}
	if members[1].Status != "pending" || members[2].Status != "deactivated" {
		t.Fatalf("lifecycle normalization=%#v", members)
	}
}

func TestTwingateRejectsRepeatedOrMissingCursor(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"data":{"users":{"pageInfo":{"hasNextPage":true,"endCursor":"same"},"edges":[]}}}`), nil
	})}
	_, _, err := Twingate(context.Background(), map[string]string{"network": "acme", "apiToken": "token"})
	if err != errRepeatedCursor {
		t.Fatalf("error=%v, want repeated cursor", err)
	}

	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"data":{"users":{"pageInfo":{"hasNextPage":true,"endCursor":null},"edges":[]}}}`), nil
	})}
	_, _, err = Twingate(context.Background(), map[string]string{"network": "acme", "apiToken": "token"})
	if err == nil || !strings.Contains(err.Error(), "pagination") {
		t.Fatalf("error=%v", err)
	}
}

func TestTwingateRejectsUnsafeNetworkAndSanitizesGraphQLErrors(t *testing.T) {
	_, _, err := Twingate(context.Background(), map[string]string{"network": "https://evil.example", "apiToken": "token"})
	if err == nil || !strings.Contains(err.Error(), "subdomain") {
		t.Fatalf("error=%v", err)
	}

	secret := "secret-api-token"
	useVendorTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Host != "acme.twingate.com" || request.Header.Get("X-API-KEY") != secret {
			t.Fatal("request did not target the fixed Twingate origin with its API key")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"errors":[{"message":"` + secret + `","extensions":{"code":"permission_denied"}}]}`))
	}))
	_, _, err = Twingate(context.Background(), map[string]string{"network": "acme", "apiToken": secret})
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "permission_denied") {
		t.Fatalf("unsafe GraphQL error %q", err)
	}
}

func TestTwingateRejectsMissingUsersData(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"data":{}}`), nil
	})}
	_, _, err := Twingate(context.Background(), map[string]string{"network": "acme", "apiToken": "token"})
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("error=%v", err)
	}
}

func TestTwingateTransportErrorDoesNotLeakAPIToken(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	secret := "transport-sensitive-api-token"
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport exposed " + secret)
	})}
	_, _, err := Twingate(context.Background(), map[string]string{"network": "acme", "apiToken": secret})
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "exposed") {
		t.Fatalf("unsafe transport error=%v", err)
	}
}
