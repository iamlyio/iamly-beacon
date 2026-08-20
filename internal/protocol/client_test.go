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
	"sync/atomic"
	"testing"
	"time"
)

func TestNewRejectsControlPlanePathPrefixes(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(privateKey)
	if _, err := New("https://control.example/iamly", "bcn_abcdefghijklmnopqrstuv", encoded); err == nil {
		t.Fatal("control-plane path prefix was accepted")
	}
	if _, err := New("https://control.example/", "bcn_abcdefghijklmnopqrstuv", encoded); err != nil {
		t.Fatalf("origin URL was rejected: %v", err)
	}
}

func TestNewRequiresHTTPSAndCanonicalBeaconIdentity(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(privateKey)
	validID := "bcn_abcdefghijklmnopqrstuv"
	if _, err := New("http://control.example", validID, encoded); err == nil {
		t.Fatal("non-local HTTP control plane was accepted")
	}
	if _, err := New("http://localhost:3000", validID, encoded); err != nil {
		t.Fatalf("local development control plane was rejected: %v", err)
	}
	if _, err := New("ftp://localhost:3000", validID, encoded); err == nil {
		t.Fatal("non-HTTP localhost control plane was accepted")
	}
	if _, err := New("https://control.example", "bcn_invalid", encoded); err == nil {
		t.Fatal("malformed Beacon ID was accepted")
	}
}

func TestPollSignsTheExactRequestAndParsesAJob(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seenNonces := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		beaconID := request.Header.Get("X-Iamly-Beacon")
		timestamp := request.Header.Get("X-Iamly-Timestamp")
		nonce := request.Header.Get("X-Iamly-Nonce")
		signature, decodeErr := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Iamly-Signature"))
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
		message := strings.Join([]string{"iamly-beacon-request-v1", "POST", request.URL.Path, beaconID, timestamp, nonce, base64.RawURLEncoding.EncodeToString(hash[:])}, "\n")
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
		io.WriteString(response, `{"protocolVersion":1,"job":{"id":"job_abcdefghijklmnopqrstuv","reviewRunId":42,"platforms":["github","google","slack"],"pendingPlatforms":["github","google","slack"],"leaseToken":"11111111-1111-4111-8111-111111111111","claimGeneration":1}}`)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, BeaconID: "bcn_abcdefghijklmnopqrstuv", PrivateKey: privateKey, Version: "v1.2.3", HTTPClient: server.Client()}
	job, err := client.Poll(context.Background(), []string{"github", "google", "slack"})
	if err != nil {
		t.Fatal(err)
	}
	if job == nil || job.ID != "job_abcdefghijklmnopqrstuv" || job.ReviewRunID != 42 {
		t.Fatalf("unexpected job: %#v", job)
	}
}

func TestJobValidationRejectsUnboundedOrUntrustedControlPlaneInput(t *testing.T) {
	valid := Job{
		ID:               "job_abcdefghijklmnopqrstuv",
		ReviewRunID:      42,
		Platforms:        []string{"github", "google"},
		PendingPlatforms: []string{"github"},
		LeaseToken:       "11111111-1111-4111-8111-111111111111",
		ClaimGeneration:  1,
	}
	if !validJob(valid) {
		t.Fatal("valid job was rejected")
	}

	tests := map[string]func(*Job){
		"unsafe job ID": func(job *Job) { job.ID = "job_\x1b[2J" },
		"short job ID":  func(job *Job) { job.ID = "job_123" },
		"zero review":   func(job *Job) { job.ReviewRunID = 0 },
		"zero generation": func(job *Job) {
			job.ClaimGeneration = 0
		},
		"invalid lease UUID": func(job *Job) { job.LeaseToken = "lease-123" },
		"empty platforms":    func(job *Job) { job.Platforms = nil },
		"unknown platform":   func(job *Job) { job.Platforms = []string{"dropbox"} },
		"duplicate platform": func(job *Job) { job.Platforms = []string{"github", "github"} },
		"too many platforms": func(job *Job) {
			job.Platforms = []string{"anthropic", "asana", "bamboohr", "canva", "cloudflare", "dockerhub", "figma", "gcp", "github", "google", "linear", "notion", "npmjs", "openai", "slack", "tailscale", "twingate", "vercel", "zoom", "github"}
		},
		"empty pending platforms": func(job *Job) { job.PendingPlatforms = nil },
		"unknown pending platform": func(job *Job) {
			job.PendingPlatforms = []string{"dropbox"}
		},
		"duplicate pending platform": func(job *Job) {
			job.PendingPlatforms = []string{"github", "github"}
		},
		"pending platform outside request": func(job *Job) {
			job.PendingPlatforms = []string{"slack"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			job := valid
			job.Platforms = append([]string(nil), valid.Platforms...)
			job.PendingPlatforms = append([]string(nil), valid.PendingPlatforms...)
			mutate(&job)
			if validJob(job) {
				t.Fatalf("invalid job accepted: %#v", job)
			}
		})
	}
}

func TestPollRejectsMalformedJobResponse(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		io.WriteString(response, `{"protocolVersion":1,"job":{"id":"job_123","reviewRunId":42,"platforms":["github"],"pendingPlatforms":["github"],"leaseToken":"11111111-1111-4111-8111-111111111111","claimGeneration":1}}`)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, BeaconID: "bcn_abcdefghijklmnopqrstuv", PrivateKey: privateKey, HTTPClient: server.Client()}
	if job, err := client.Poll(context.Background(), []string{"github"}); err == nil || job != nil {
		t.Fatalf("malformed job accepted: job=%#v err=%v", job, err)
	}
}

func TestProtocolClientRejectsRedirectsWithoutMutatingCustomClient(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	var targetReached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetReached.Store(true)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", target.URL+"/internal")
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	custom := redirect.Client()
	if custom.CheckRedirect != nil {
		t.Fatal("test requires the custom client to begin without a redirect policy")
	}
	client := Client{BaseURL: redirect.URL, BeaconID: "bcn_abcdefghijklmnopqrstuv", PrivateKey: privateKey, HTTPClient: custom}
	if _, err := client.Poll(context.Background(), []string{"github"}); err == nil {
		t.Fatal("redirect response was accepted")
	}
	if targetReached.Load() {
		t.Fatal("protocol client followed a control-plane redirect")
	}
	if custom.CheckRedirect != nil {
		t.Fatal("protocol client mutated the caller's HTTP client")
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

func TestUploadRejectsOversizedResultBeforeNetwork(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	var reached atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	defer server.Close()
	client := Client{BaseURL: server.URL, BeaconID: "bcn_abcdefghijklmnopqrstuv", PrivateKey: privateKey, HTTPClient: server.Client()}
	oversized := strings.Repeat("x", maxResultUploadBytes)
	err := client.Upload(context.Background(), Job{ID: "job_123", LeaseToken: "lease-123", ClaimGeneration: 1}, Result{
		Platform: "slack", CapturedAt: time.Now().Format(time.RFC3339), Error: &oversized,
	})
	if err == nil || !strings.Contains(err.Error(), "32 MiB upload limit") {
		t.Fatalf("error = %v", err)
	}
	if reached.Load() {
		t.Fatal("oversized upload reached the network")
	}
}

func TestControlPlaneErrorTextIsBoundedAndSafe(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantCode  string
		forbidden string
	}{
		{name: "known machine code", body: `{"error":"job_not_active"}`, wantCode: "job_not_active"},
		{name: "terminal controls", body: "{\"error\":\"unauthorized\\n\\u001b[2Jforged\"}", forbidden: "forged"},
		{name: "free form text", body: `{"error":"database detail leaked"}`, forbidden: "database detail"},
		{name: "oversized", body: `{"error":"` + strings.Repeat("a", maxControlPlaneError+1) + `"}`, forbidden: strings.Repeat("a", maxControlPlaneError+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := responseError(http.StatusBadRequest, []byte(test.body))
			if test.wantCode != "" && !strings.Contains(err.Error(), test.wantCode) {
				t.Fatalf("error = %q, want safe code %q", err, test.wantCode)
			}
			if test.forbidden != "" && strings.Contains(err.Error(), test.forbidden) {
				t.Fatalf("unsafe control-plane text escaped sanitization: %q", err)
			}
		})
	}
}

func TestUploadRetriesTransientFailureWithFreshSignedNonce(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	attempts := 0
	nonces := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		attempts++
		nonce := request.Header.Get("X-Iamly-Nonce")
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
