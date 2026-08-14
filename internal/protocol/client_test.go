package protocol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPollSignsTheExactRequestAndParsesAJob(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seenNonces := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		beaconID := request.Header.Get("X-Reviam-Beacon")
		timestamp := request.Header.Get("X-Reviam-Timestamp")
		nonce := request.Header.Get("X-Reviam-Nonce")
		signature, decodeErr := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Reviam-Signature"))
		if decodeErr != nil || len(signature) != ed25519.SignatureSize {
			t.Error("invalid signature encoding")
		}
		if seenNonces[nonce] {
			t.Error("nonce was reused")
		}
		seenNonces[nonce] = true
		seconds, parseErr := strconv.ParseInt(timestamp, 10, 64)
		if parseErr != nil || time.Since(time.Unix(seconds, 0)) > 2*time.Minute {
			t.Error("invalid timestamp")
		}
		hash := sha256.Sum256(body)
		message := strings.Join([]string{"reviam-beacon-request-v1", "POST", request.URL.Path, beaconID, timestamp, nonce, base64.RawURLEncoding.EncodeToString(hash[:])}, "\n")
		if !ed25519.Verify(publicKey, []byte(message), signature) {
			t.Error("request signature does not verify")
		}
		var payload struct {
			ProtocolVersion int      `json:"protocolVersion"`
			Integrations    []string `json:"integrations"`
			Hostname        string   `json:"hostname"`
			PrivateIPs      []string `json:"privateIps"`
			Version         string   `json:"version"`
		}
		if json.Unmarshal(body, &payload) != nil || payload.ProtocolVersion != 1 ||
			strings.Join(payload.Integrations, ",") != "github,google,slack" ||
			payload.Hostname == "" || payload.Version != "v1.2.3" {
			t.Error("unexpected poll payload")
		}
		for _, address := range payload.PrivateIPs {
			if ip := net.ParseIP(address); ip == nil || !ip.IsPrivate() {
				t.Errorf("unexpected private IP %q", address)
			}
		}
		response.Header().Set("Content-Type", "application/json")
		io.WriteString(response, `{"protocolVersion":1,"job":{"id":"job_123","reviewRunId":42,"platforms":["github","google","slack"],"pendingPlatforms":["github","google","slack"],"leaseToken":"lease-123","claimGeneration":1}}`)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, BeaconID: "bcn_abcdefghijklmnopqrstuv", PrivateKey: privateKey, Version: "v1.2.3", HTTPClient: server.Client()}
	job, err := client.Poll(context.Background(), []string{"github", "google", "slack"})
	if err != nil {
		t.Fatal(err)
	}
	if job == nil || job.ID != "job_123" || job.ReviewRunID != 42 {
		t.Fatalf("unexpected job: %#v", job)
	}
}

func TestControlPlaneErrorsNeverEchoTheRequestBody(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		io.WriteString(response, `{"error":"unauthorized"}`)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, BeaconID: "bcn_abcdefghijklmnopqrstuv", PrivateKey: privateKey, HTTPClient: server.Client()}
	secret := "must-never-appear-in-an-error"
	err := client.Upload(context.Background(), Job{ID: "job_123", LeaseToken: "lease-123", ClaimGeneration: 1}, Result{Platform: "slack", CapturedAt: time.Now().Format(time.RFC3339), Error: &secret})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestUploadRetriesTransientFailureWithFreshSignedNonce(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	attempts := 0
	nonces := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		attempts++
		nonce := request.Header.Get("X-Reviam-Nonce")
		if nonce == "" || nonces[nonce] {
			t.Errorf("upload attempt reused or omitted nonce %q", nonce)
		}
		nonces[nonce] = true
		if attempts == 1 {
			http.Error(response, "temporary", http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		io.WriteString(response, `{"ok":true,"complete":true}`)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, BeaconID: "bcn_retry", PrivateKey: privateKey, HTTPClient: server.Client()}
	err := client.Upload(context.Background(), Job{
		ID: "job_retry", LeaseToken: "lease-retry", ClaimGeneration: 1,
	}, Result{Platform: "github", CapturedAt: time.Now().UTC().Format(time.RFC3339Nano), Members: []Member{}})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || len(nonces) != 2 {
		t.Fatalf("attempts=%d nonces=%d, want two", attempts, len(nonces))
	}
}
