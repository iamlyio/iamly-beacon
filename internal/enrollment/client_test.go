package enrollment

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestGenerateIdentityUsesRawEd25519Keys(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(identity.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("public key is not raw Ed25519: len=%d err=%v", len(publicKey), err)
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(identity.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		t.Fatalf("private key is not raw Ed25519: len=%d err=%v", len(privateKey), err)
	}
	message := []byte("Beacon proof")
	signature := ed25519.Sign(privateKey, message)
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("generated key pair cannot sign and verify")
	}
}

func TestEnrollDoesNotFollowRedirectWithToken(t *testing.T) {
	received := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		received++
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	_, err := (Client{HTTPClient: redirect.Client()}).Enroll(context.Background(), redirect.URL, "secret-token", "Production", "public", "v1")
	if err == nil {
		t.Fatal("Enroll() accepted a redirect")
	}
	if received != 0 {
		t.Fatalf("redirect target received %d requests", received)
	}
}

func TestEnrollDoesNotIncludeUntrustedResponseErrorInReturnedError(t *testing.T) {
	const token = "do-not-echo-this-token"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"error":"do-not-echo-this-token"}`))
	}))
	defer server.Close()

	_, err := (Client{HTTPClient: server.Client()}).Enroll(context.Background(), server.URL, token, "Production", "public", "v1")
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("Enroll() error = %q", err)
	}
}

func TestEnrollRetriesAmbiguousFailureWithExactSameIdentity(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		bodies = append(bodies, body)
		attempt := len(bodies)
		mu.Unlock()
		if attempt == 1 {
			hijacker, ok := writer.(http.Hijacker)
			if !ok {
				t.Error("response writer cannot hijack connection")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"beacon":{"id":"bcn_abcdefghijklmnopqrstuv","name":"Production"},"protocolVersion":1}`))
	}))
	defer server.Close()

	got, err := (Client{HTTPClient: server.Client()}).Enroll(context.Background(), server.URL, "same-token", "Production", "same-public-key", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if got.BeaconID != "bcn_abcdefghijklmnopqrstuv" || len(bodies) != 2 {
		t.Fatalf("result=%#v attempts=%d", got, len(bodies))
	}
	if bodies[0]["token"] != bodies[1]["token"] || bodies[0]["publicKey"] != bodies[1]["publicKey"] {
		t.Fatalf("retry changed identity: %#v", bodies)
	}
}

func TestEnrollSendsContractAndReadsAssignedIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/beacon/enroll" || request.Method != http.MethodPost {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["token"] != "one-time-secret" || body["name"] != "Production" || body["publicKey"] != "public" || body["version"] != "v1.2.3" {
			t.Fatalf("body = %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"beacon":{"id":"bcn_abcdefghijklmnopqrstuv","name":"Production","enrolledAt":"now"},"protocolVersion":1}`))
	}))
	defer server.Close()

	got, err := (Client{HTTPClient: server.Client()}).Enroll(context.Background(), server.URL, "one-time-secret", "Production", "public", "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if got.BeaconID != "bcn_abcdefghijklmnopqrstuv" || got.BeaconName != "Production" {
		t.Fatalf("result = %#v", got)
	}
}
