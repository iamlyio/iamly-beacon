package collector

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func gcpTestCredentials(t *testing.T) map[string]string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"clientEmail":   "beacon@example-project.iam.gserviceaccount.com",
		"resourceScope": "projects/example-project",
		"privateKey":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})),
	}
}

func TestGCPCollectsDirectPrincipalsAcrossPages(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	assetRequests := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "oauth2.googleapis.com":
			blob, _ := io.ReadAll(request.Body)
			form, err := url.ParseQuery(string(blob))
			if err != nil || form.Get("grant_type") == "" || form.Get("assertion") == "" {
				t.Fatal("GCP OAuth assertion was not encoded correctly")
			}
			parts := strings.Split(form.Get("assertion"), ".")
			claimsBlob, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatal(err)
			}
			var claims map[string]any
			if json.Unmarshal(claimsBlob, &claims) != nil || claims["iss"] != "beacon@example-project.iam.gserviceaccount.com" || claims["scope"] != gcpOAuthScope {
				t.Fatalf("unexpected JWT claims %#v", claims)
			}
			return jsonResponse(http.StatusOK, `{"access_token":"gcp-access-token"}`), nil
		case "cloudasset.googleapis.com":
			assetRequests++
			if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer gcp-access-token" {
				t.Fatal("GCP IAM request was not read-only or authorized")
			}
			if request.URL.Path != "/v1/projects/example-project:searchAllIamPolicies" || request.URL.Query().Get("pageSize") != "500" {
				t.Fatalf("unexpected GCP endpoint %s", request.URL.String())
			}
			if assetRequests == 1 {
				if request.URL.Query().Get("pageToken") != "" {
					t.Fatal("first request unexpectedly had a page token")
				}
				return jsonResponse(http.StatusOK, `{"results":[{"policy":{"bindings":[{"role":"roles/viewer","members":["user:ada@example.com","serviceAccount:runner@example-project.iam.gserviceaccount.com","group:ignored@example.com"]}]}}],"nextPageToken":"page-2"}`), nil
			}
			if request.URL.Query().Get("pageToken") != "page-2" {
				t.Fatal("second page token missing")
			}
			return jsonResponse(http.StatusOK, `{"results":[{"policy":{"bindings":[{"role":"roles/logging.viewer","members":["user:ada@example.com","deleted:user:old@example.com?uid=123"]}]}}]}`), nil
		}
		t.Fatalf("unexpected GCP host %s", request.URL.Host)
		return nil, nil
	})}

	members, spend, err := GCP(context.Background(), gcpTestCredentials(t))
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 3 || assetRequests != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, assetRequests)
	}
	byEmail := map[string]int{}
	for index, member := range members {
		if member.Email != nil {
			byEmail[*member.Email] = index
		}
	}
	ada := members[byEmail["ada@example.com"]]
	if ada.Role == nil || *ada.Role != "roles/logging.viewer, roles/viewer" || ada.Status != "active" {
		t.Fatalf("Ada principal=%#v", ada)
	}
	service := members[byEmail["runner@example-project.iam.gserviceaccount.com"]]
	if service.Role == nil || *service.Role != "service account · roles/viewer" {
		t.Fatalf("service account=%#v", service)
	}
	if old := members[byEmail["old@example.com"]]; old.Status != "deactivated" {
		t.Fatalf("deleted principal=%#v", old)
	}
}

func TestGCPRejectsInvalidScopeBeforeNetworkAccess(t *testing.T) {
	credentials := gcpTestCredentials(t)
	credentials["resourceScope"] = "projects/example/../../attacker"
	_, _, err := GCP(context.Background(), credentials)
	if err == nil || !strings.Contains(err.Error(), "resourceScope") {
		t.Fatalf("error=%v", err)
	}
}

func TestGCPRejectsRepeatedCursorAndDoesNotLeakCredentials(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "oauth2.googleapis.com" {
			return jsonResponse(http.StatusOK, `{"access_token":"sensitive-access-token"}`), nil
		}
		return jsonResponse(http.StatusOK, `{"results":[],"nextPageToken":"same"}`), nil
	})}
	credentials := gcpTestCredentials(t)
	_, _, err := GCP(context.Background(), credentials)
	if err != errRepeatedCursor {
		t.Fatalf("error=%v, want repeated cursor", err)
	}

	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusForbidden, `{"error":"`+credentials["privateKey"]+`"}`), nil
	})}
	_, _, err = GCP(context.Background(), credentials)
	if err == nil || strings.Contains(err.Error(), credentials["privateKey"]) {
		t.Fatalf("credential leaked in error %q", err)
	}
}

func TestGCPTransportErrorDoesNotLeakPrivateKey(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	credentials := gcpTestCredentials(t)
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("transport exposed " + credentials["privateKey"])
	})}
	_, _, err := GCP(context.Background(), credentials)
	if err == nil || strings.Contains(err.Error(), credentials["privateKey"]) || strings.Contains(err.Error(), "exposed") {
		t.Fatalf("unsafe transport error=%v", err)
	}
}
