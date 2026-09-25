package collector

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const gcpTestRing = "projects/example-project/locations/us-central1/keyRings/inventory"
const gcpTestKey = gcpTestRing + "/cryptoKeys/payments"

func gcpKeysFixtureTransport(t *testing.T, credentials map[string]string, handler func(*http.Request) (int, string)) {
	t.Helper()
	block, _ := pem.Decode([]byte(credentials["privateKey"]))
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := parsed.(*rsa.PrivateKey)
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "oauth2.googleapis.com" {
			body, _ := io.ReadAll(request.Body)
			form, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(form.Get("assertion"), ".")
			if len(parts) != 3 {
				t.Fatal("missing signed service-account assertion")
			}
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
				t.Fatal("OAuth assertion signature invalid")
			}
			return jsonResponse(200, `{"access_token":"fixture-gcp-access-token"}`), nil
		}
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer fixture-gcp-access-token" {
			t.Fatal("GCP inventory request is not a read-only authenticated request")
		}
		if request.URL.Host != "cloudasset.googleapis.com" && request.URL.Host != "cloudkms.googleapis.com" {
			t.Fatal("unexpected GCP metadata host")
		}
		status, body := handler(request)
		return jsonResponse(status, body), nil
	})}
}

func TestGCPKeysSignedScopedPaginationAndVersions(t *testing.T) {
	credentials := gcpTestCredentials(t)
	credentials["resourceScope"] = "organizations/1234"
	assetPages, keyPages, versionPages := 0, 0, 0
	gcpKeysFixtureTransport(t, credentials, func(request *http.Request) (int, string) {
		switch request.URL.Path {
		case "/v1/organizations/1234:searchAllResources":
			assetPages++
			if request.URL.Query().Get("assetTypes") != "cloudkms.googleapis.com/KeyRing" {
				t.Fatal("GCP discovery not limited to key rings")
			}
			if assetPages == 1 {
				return 200, `{"results":[{"name":"//cloudkms.googleapis.com/` + gcpTestRing + `","organization":"organizations/1234"}],"nextPageToken":"asset-2"}`
			}
			if request.URL.Query().Get("pageToken") != "asset-2" {
				t.Fatal("asset cursor missing")
			}
			return 200, `{"results":[]}`
		case "/v1/" + gcpTestRing + "/cryptoKeys":
			keyPages++
			if request.URL.Query().Get("versionView") != "BASIC" {
				t.Fatal("unexpected primary-version view")
			}
			if keyPages == 1 {
				return 200, `{"cryptoKeys":[{"name":"` + gcpTestKey + `","purpose":"ENCRYPT_DECRYPT","createTime":"2024-01-01T02:00:00+02:00","rotationPeriod":"7776000s","nextRotationTime":"2025-01-01T00:00:00Z","primary":{"name":"` + gcpTestKey + `/cryptoKeyVersions/2","state":"ENABLED"},"labels":{"owner":"must-not-infer"},"secretKey":"must-not-serialize"}],"nextPageToken":"key-2"}`
			}
			if request.URL.Query().Get("pageToken") != "key-2" {
				t.Fatal("key cursor missing")
			}
			return 200, `{"cryptoKeys":[]}`
		case "/v1/" + gcpTestKey + "/cryptoKeyVersions":
			versionPages++
			if request.URL.Query().Get("view") != "BASIC" {
				t.Fatal("unexpected version view")
			}
			if versionPages == 1 {
				return 200, `{"cryptoKeyVersions":[{"name":"` + gcpTestKey + `/cryptoKeyVersions/1","state":"DESTROY_SCHEDULED","createTime":"2024-01-01T00:00:00Z","destroyTime":"2027-01-01T00:00:00Z","algorithm":"GOOGLE_SYMMETRIC_ENCRYPTION","protectionLevel":"HSM"}],"nextPageToken":"version-2"}`
			}
			if request.URL.Query().Get("pageToken") != "version-2" {
				t.Fatal("version cursor missing")
			}
			return 200, `{"cryptoKeyVersions":[{"name":"` + gcpTestKey + `/cryptoKeyVersions/2","state":"ENABLED","createTime":"2024-02-01T00:00:00Z"}]}`
		default:
			t.Fatalf("unexpected GCP operation %s", request.URL.Path)
		}
		return 500, `{}`
	})
	keys, coverage := CollectKeys(context.Background(), "gcp", credentials)
	if len(keys) != 3 || coverage[0].Status != "complete" || coverage[0].ResourcesTotal != 1 || coverage[0].ResourcesScanned != 1 || assetPages != 2 || keyPages != 2 || versionPages != 2 {
		t.Fatalf("keys=%#v coverage=%#v pages=%d/%d/%d", keys, coverage, assetPages, keyPages, versionPages)
	}
	if keys[0].Status != "unknown" || keys[1].Status != "pending_deletion" || keys[2].Status != "active" || keys[0].CreatedAt == nil || *keys[0].CreatedAt != "2024-01-01T00:00:00Z" {
		t.Fatalf("incorrect key/version metadata %#v", keys)
	}
	for _, key := range keys {
		if key.LastUsedAt != nil || key.Owner != nil || key.CreatedBy != nil || key.ExpiresAt != nil {
			t.Fatal("unsupported attribution/expiry invented")
		}
	}
	blob, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{credentials["privateKey"], "fixture-gcp-access-token", "must-not-serialize", "must-not-infer"} {
		if strings.Contains(string(blob), secret) {
			t.Fatal("metadata serialization leaked a secret or inferred ownership")
		}
	}
}

func TestGCPKeyPermissionFailureRetainsLogicalKeyAndMembers(t *testing.T) {
	credentials := gcpTestCredentials(t)
	gcpKeysFixtureTransport(t, credentials, func(request *http.Request) (int, string) {
		switch request.URL.Path {
		case "/v1/projects/example-project:searchAllIamPolicies":
			return 200, `{"results":[{"policy":{"bindings":[{"role":"roles/viewer","members":["user:ada@example.com"]}]}}]}`
		case "/v1/projects/example-project:searchAllResources":
			return 200, `{"results":[{"name":"//cloudkms.googleapis.com/` + gcpTestRing + `"}]}`
		case "/v1/" + gcpTestRing + "/cryptoKeys":
			return 200, `{"cryptoKeys":[{"name":"` + gcpTestKey + `","purpose":"ENCRYPT_DECRYPT","createTime":"2024-01-01T00:00:00Z"}]}`
		case "/v1/" + gcpTestKey + "/cryptoKeyVersions":
			return 403, `{"error":{"message":"fixture-gcp-access-token"}}`
		default:
			t.Fatalf("unexpected GCP path %s", request.URL.Path)
		}
		return 500, `{}`
	})
	members, _, err := GCP(context.Background(), credentials)
	if err != nil || len(members) != 1 || members[0].Email == nil || *members[0].Email != "ada@example.com" {
		t.Fatal("existing GCP roster collection failed")
	}
	keys, coverage := CollectKeys(context.Background(), "gcp", credentials)
	if len(keys) != 1 || keys[0].ID != gcpTestKey || keys[0].CreatedAt == nil || coverage[0].Status != "partial" || coverage[0].ResourcesScanned != 0 || coverage[0].ResourcesTotal != 1 {
		t.Fatalf("keys=%#v coverage=%#v", keys, coverage)
	}
}

func TestGCPKeysRejectsOutOfScopeAndRepeatedCursor(t *testing.T) {
	credentials := gcpTestCredentials(t)
	credentials["resourceScope"] = "folders/1234"
	pages := 0
	gcpKeysFixtureTransport(t, credentials, func(request *http.Request) (int, string) {
		if request.URL.Path != "/v1/folders/1234:searchAllResources" {
			t.Fatal("out-of-scope KMS resource was followed")
		}
		pages++
		return 200, `{"results":[{"name":"//cloudkms.googleapis.com/` + gcpTestRing + `","folders":["folders/9999"]},{"name":"//attacker.example/projects/example-project/locations/global/keyRings/stolen","folders":["folders/1234"]}],"nextPageToken":"repeat"}`
	})
	keys, coverage := CollectKeys(context.Background(), "gcp", credentials)
	if len(keys) != 0 || coverage[0].Status != "partial" || coverage[0].ResourcesTotal != 0 || pages != 2 {
		t.Fatalf("keys=%#v coverage=%#v pages=%d", keys, coverage, pages)
	}
}

func TestGCPKeysDiscoveryDeniedIsUnavailable(t *testing.T) {
	credentials := gcpTestCredentials(t)
	gcpKeysFixtureTransport(t, credentials, func(*http.Request) (int, string) { return 403, `{"error":{"message":"fixture-gcp-access-token"}}` })
	keys, coverage := CollectKeys(context.Background(), "gcp", credentials)
	if len(keys) != 0 || coverage[0].Status != "unavailable" || strings.Contains(*coverage[0].Message, "fixture-gcp-access-token") {
		t.Fatalf("keys=%#v coverage=%#v", keys, coverage)
	}
}

func TestCloudKeyRequestLimitStopsFurtherCalls(t *testing.T) {
	inventory := &cloudKeyInventory{requests: maxCloudKeyRequests}
	if err := inventory.request(); err != errCloudKeyLimit || inventory.requests != maxCloudKeyRequests {
		t.Fatalf("request boundary err=%v count=%d", err, inventory.requests)
	}
}
