package collector

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestTailscaleUsesReadOnlyOAuthAndNormalizesUsers(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	requests := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch request.URL.Path {
		case "/api/v2/oauth/token":
			if request.Method != http.MethodPost {
				t.Fatal("token exchange must use POST")
			}
			body, _ := io.ReadAll(request.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("client_id") != "client-id" || form.Get("client_secret") != "client-secret" || form.Get("grant_type") != "client_credentials" || form.Get("scope") != "users:read" {
				t.Fatalf("unexpected OAuth form %#v", form)
			}
			return jsonResponse(http.StatusOK, `{"access_token":"short-lived-token"}`), nil
		case "/api/v2/tailnet/-/users":
			if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer short-lived-token" {
				t.Fatal("users request was not read-only or authorized")
			}
			if request.URL.Query().Get("type") != "all" {
				t.Fatal("shared tailnet users were not requested")
			}
			return jsonResponse(http.StatusOK, `{"users":[{"id":"1","displayName":"Ada Lovelace","loginName":"ada@example.com","created":"2025-01-02T03:04:05Z","type":"member","role":"owner","status":"idle","lastSeen":"2026-08-17T12:00:00Z"},{"id":"2","loginName":"pending@example.com","type":"member","role":"member","status":"needs-approval"},{"id":"3","loginName":"off@example.com","type":"member","role":"member","status":"over-billing-limit"},{"id":"4","loginName":"partner@example.net","type":"shared","role":"member","status":"active"}]}`), nil
		}
		t.Fatalf("unexpected Tailscale request %s", request.URL.String())
		return nil, nil
	})}

	members, spend, err := Tailscale(context.Background(), map[string]string{"clientId": "client-id", "clientSecret": "client-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 4 || requests != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Status != "active" || members[0].Email == nil || *members[0].Email != "ada@example.com" || members[0].LastLoginAt == nil {
		t.Fatalf("active user=%#v", members[0])
	}
	if members[1].Status != "pending" || members[2].Status != "suspended" {
		t.Fatalf("lifecycle normalization=%#v", members)
	}
	if members[3].Role == nil || *members[3].Role != "member · shared" {
		t.Fatalf("shared user=%#v", members[3])
	}
}

func TestTailscaleErrorsDoNotLeakClientSecret(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	secret := "super-sensitive-client-secret"
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusUnauthorized, `{"message":"`+secret+`"}`), nil
	})}
	_, _, err := Tailscale(context.Background(), map[string]string{"clientId": "client-id", "clientSecret": secret})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked in error %q", err)
	}
}

func TestTailscaleTransportErrorDoesNotLeakClientSecret(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	secret := "transport-sensitive-client-secret"
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport exposed " + secret)
	})}
	_, _, err := Tailscale(context.Background(), map[string]string{"clientId": "client-id", "clientSecret": secret})
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "exposed") {
		t.Fatalf("unsafe transport error=%v", err)
	}
}

func TestTailscaleRejectsOversizedUserResponse(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/v2/oauth/token" {
			return jsonResponse(http.StatusOK, `{"access_token":"token"}`), nil
		}
		return jsonResponse(http.StatusOK, strings.Repeat("x", (32<<20)+1)), nil
	})}
	_, _, err := Tailscale(context.Background(), map[string]string{"clientId": "client-id", "clientSecret": "client-secret"})
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("error=%v", err)
	}
}

func TestTailscaleRejectsMissingUsersEnvelope(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/api/v2/oauth/token" {
			return jsonResponse(http.StatusOK, `{"access_token":"token"}`), nil
		}
		return jsonResponse(http.StatusOK, `{}`), nil
	})}
	_, _, err := Tailscale(context.Background(), map[string]string{"clientId": "client-id", "clientSecret": "client-secret"})
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("error=%v", err)
	}
}
