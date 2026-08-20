package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iamlyio/iamly-beacon/internal/collector"
	"github.com/iamlyio/iamly-beacon/internal/config"
	"github.com/iamlyio/iamly-beacon/internal/enrollment"
	"github.com/iamlyio/iamly-beacon/internal/protocol"
	"github.com/iamlyio/iamly-beacon/internal/vault"
)

const testKeyName = "projects/acme/locations/global/keyRings/iamly/cryptoKeys/beacon"

func TestExecuteBeaconJobUploadsConnectorFailureWithoutStoppingSuccessfulCollectors(t *testing.T) {
	original := collector.Supported
	t.Cleanup(func() { collector.Supported = original })
	collector.Supported = map[string]collector.Collector{
		"google": func(context.Context, map[string]string) ([]protocol.Member, *protocol.Spend, error) {
			email := "person@example.com"
			return []protocol.Member{{Email: &email, Status: "active"}}, nil, nil
		},
		"github": func(context.Context, map[string]string) ([]protocol.Member, *protocol.Spend, error) {
			return nil, nil, errors.New("GitHub API unavailable")
		},
	}

	var mutex sync.Mutex
	results := map[string]protocol.Result{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/results") {
			http.Error(response, "unexpected path", http.StatusNotFound)
			return
		}
		var result protocol.Result
		if err := json.NewDecoder(request.Body).Decode(&result); err != nil {
			http.Error(response, "invalid body", http.StatusBadRequest)
			return
		}
		mutex.Lock()
		results[result.Platform] = result
		mutex.Unlock()
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"complete":true}`))
	}))
	t.Cleanup(server.Close)

	identity, err := enrollment.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := protocol.New(server.URL, "bcn_abcdefghijklmnopqrstuv", identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	output := &bytes.Buffer{}
	application := &App{stdout: output}
	job := protocol.Job{
		ID: "job_test", Platforms: []string{"google", "github"},
		LeaseToken: "lease_test", ClaimGeneration: 1,
	}
	credentials := map[string]map[string]string{
		"google": {"configured": "yes"},
		"github": {"configured": "yes"},
	}
	if err := application.executeBeaconJob(context.Background(), client, job, credentials); err != nil {
		t.Fatal(err)
	}

	mutex.Lock()
	defer mutex.Unlock()
	if len(results) != 2 {
		t.Fatalf("uploaded %d results, want 2", len(results))
	}
	if got := results["google"]; got.Error != nil || len(got.Members) != 1 {
		t.Fatalf("google result = %#v, want one successful member", got)
	}
	if got := results["github"]; got.Error == nil || *got.Error != "GitHub API unavailable" || len(got.Members) != 0 {
		t.Fatalf("github result = %#v, want an isolated connector failure", got)
	}
	if !strings.Contains(output.String(), "collection complete") {
		t.Fatalf("output = %q, want collection completion", output.String())
	}
}

func TestExecuteBeaconJobBoundsCollectorTimeAndCapturesAfterCollection(t *testing.T) {
	original := collector.Supported
	t.Cleanup(func() { collector.Supported = original })
	collector.Supported = map[string]collector.Collector{
		"google": func(ctx context.Context, _ map[string]string) ([]protocol.Member, *protocol.Spend, error) {
			<-ctx.Done()
			return nil, nil, ctx.Err()
		},
	}

	resultChannel := make(chan protocol.Result, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var result protocol.Result
		if err := json.NewDecoder(request.Body).Decode(&result); err != nil {
			http.Error(response, "invalid body", http.StatusBadRequest)
			return
		}
		resultChannel <- result
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"complete":true}`))
	}))
	t.Cleanup(server.Close)

	identity, err := enrollment.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := protocol.New(server.URL, "bcn_cdefghijklmnopqrstuvwx", identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC()
	application := &App{stdout: io.Discard, collectionTimeout: 10 * time.Millisecond}
	job := protocol.Job{
		ID: "job_timeout_test", Platforms: []string{"google"},
		LeaseToken: "lease_timeout_test", ClaimGeneration: 1,
	}
	if err := application.executeBeaconJob(context.Background(), client, job, map[string]map[string]string{
		"google": {"configured": "yes"},
	}); err != nil {
		t.Fatal(err)
	}

	result := <-resultChannel
	if result.Error == nil || *result.Error != "collection exceeded the 10 minute deadline" {
		t.Fatalf("result error = %v", result.Error)
	}
	capturedAt, err := time.Parse(time.RFC3339Nano, result.CapturedAt)
	if err != nil || capturedAt.Before(startedAt) {
		t.Fatalf("capturedAt = %q, startedAt = %s, error = %v", result.CapturedAt, startedAt, err)
	}
}

func TestExecuteBeaconJobUploadsEnrichedAppBeforeOtherConnectorsFinish(t *testing.T) {
	original := collector.Supported
	t.Cleanup(func() { collector.Supported = original })
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	lastSeen := "2026-08-14T09:30:00Z"
	name := "Ada Lovelace"
	role := "administrator"
	billable := true
	collector.Supported = map[string]collector.Collector{
		"google": func(context.Context, map[string]string) ([]protocol.Member, *protocol.Spend, error) {
			return []protocol.Member{{
				Email: stringPointer("ada@example.com"), Name: &name, Status: "active",
				Role: &role, LastLoginAt: &lastSeen, Billable: &billable,
			}}, nil, nil
		},
		"github": func(ctx context.Context, _ map[string]string) ([]protocol.Member, *protocol.Spend, error) {
			close(slowStarted)
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-releaseSlow:
				return []protocol.Member{}, nil, nil
			}
		},
	}

	googleUploaded := make(chan protocol.Result, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var result protocol.Result
		if err := json.NewDecoder(request.Body).Decode(&result); err != nil {
			http.Error(response, "invalid body", http.StatusBadRequest)
			return
		}
		if result.Platform == "google" {
			googleUploaded <- result
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"complete":true}`))
	}))
	t.Cleanup(server.Close)

	identity, err := enrollment.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := protocol.New(server.URL, "bcn_bcdefghijklmnopqrstuvw", identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	application := &App{stdout: io.Discard}
	job := protocol.Job{
		ID: "job_stream_test", Platforms: []string{"google", "github"},
		LeaseToken: "lease_stream_test", ClaimGeneration: 1,
	}
	done := make(chan error, 1)
	go func() {
		done <- application.executeBeaconJob(context.Background(), client, job, map[string]map[string]string{
			"google": {"configured": "yes"},
			"github": {"configured": "yes"},
		})
	}()

	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("slow connector did not start")
	}
	select {
	case result := <-googleUploaded:
		if len(result.Members) != 1 || result.Members[0].Name == nil || *result.Members[0].Name != name ||
			result.Members[0].LastLoginAt == nil || *result.Members[0].LastLoginAt != lastSeen ||
			result.Members[0].Role == nil || *result.Members[0].Role != role ||
			result.Members[0].Billable == nil || !*result.Members[0].Billable {
			t.Fatalf("uploaded result was not fully enriched: %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("completed app waited for the blocked sibling connector before upload")
	}
	close(releaseSlow)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func stringPointer(value string) *string { return &value }

type testKMS struct {
	selfTested bool
	enrolled   bool
	wrapCalls  int
}

func (k *testKMS) Wrap(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	k.wrapCalls++
	if k.enrolled && !k.selfTested {
		return nil, errors.New("vault save happened before self-test")
	}
	return append([]byte(nil), plaintext...), nil
}

func (k *testKMS) Unwrap(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	if k.wrapCalls == 1 {
		k.selfTested = true
	}
	return append([]byte(nil), ciphertext...), nil
}

func (k *testKMS) Close() error { return nil }

type testEnroller struct {
	kms   *testKMS
	calls int
}

type staticEnroller struct{}

func (staticEnroller) Enroll(_ context.Context, _, token, name, publicKey, _ string) (enrollment.Result, error) {
	if token == "" || name == "" || publicKey == "" {
		return enrollment.Result{}, errors.New("missing enrollment input")
	}
	return enrollment.Result{BeaconID: "bcn_abcdefghijklmnopqrstuv", BeaconName: name}, nil
}

func (e *testEnroller) Enroll(_ context.Context, controlPlane, token, name, publicKey, version string) (enrollment.Result, error) {
	e.calls++
	if !e.kms.selfTested {
		return enrollment.Result{}, errors.New("enrollment happened before KMS self-test")
	}
	if controlPlane != betaControlPlane || token != testToken() || name != "Production" || publicKey == "" || version != "v1.2.3" {
		return enrollment.Result{}, errors.New("unexpected enrollment input")
	}
	e.kms.enrolled = true
	return enrollment.Result{BeaconID: "bcn_abcdefghijklmnopqrstuv", BeaconName: "Production"}, nil
}

func TestConfigureEnrollsAfterKMSSelfTestAndPersistsIdentityWithoutToken(t *testing.T) {
	kms := &testKMS{}
	enroller := &testEnroller{kms: kms}
	identity, err := enrollment.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault.bin")
	application := &App{
		version: "v1.2.3",
		paths:   config.Paths{Vault: path},
		stdin:   bytes.NewBufferString(testToken() + "\n"),
		newKeyWrapper: func(context.Context, vault.Provider, string, bool) (kmsWrapper, error) {
			return kms, nil
		},
		enroller: enroller,
		generateIdentity: func() (enrollment.Identity, error) {
			return identity, nil
		},
	}
	arguments := []string{
		"--kms-key", testKeyName,
		"--name", "Production",
		"--enrollment-token-stdin",
	}
	if err := application.configure(context.Background(), arguments); err != nil {
		t.Fatal(err)
	}
	if enroller.calls != 1 || kms.wrapCalls != 2 {
		t.Fatalf("enroll calls=%d wrap calls=%d, want 1 and 2", enroller.calls, kms.wrapCalls)
	}
	data, err := vault.NewStore(path, vault.ProviderGoogleKMS, testKeyName, kms).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.ControlPlane.BeaconID != "bcn_abcdefghijklmnopqrstuv" || data.ControlPlane.BeaconName != "Production" ||
		data.ControlPlane.SigningPrivateKey != identity.PrivateKey || data.ControlPlane.SigningPublicKey != identity.PublicKey {
		t.Fatalf("stored identity = %#v", data.ControlPlane)
	}
}

func TestConfigureLocalCreatesUsableRestrictedVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BEACON_HOME", home)
	application, err := New("v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	application.stdin = bytes.NewBufferString(testToken() + "\n")
	application.enroller = staticEnroller{}
	if err := application.configure(context.Background(), []string{
		"--local",
		"--name", "Development",
		"--enrollment-token-stdin",
	}); err != nil {
		t.Fatal(err)
	}
	metadata, err := vault.ReadMetadata(application.paths.Vault)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Provider != vault.ProviderLocal || metadata.KeyName != vault.LocalKeyName {
		t.Fatalf("metadata = %#v", metadata)
	}
	localKey, err := vault.OpenLocalKey(application.paths.LocalKey)
	if err != nil {
		t.Fatal(err)
	}
	defer localKey.Close()
	data, err := vault.NewStore(application.paths.Vault, metadata.Provider, metadata.KeyName, localKey).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.ControlPlane.BeaconID == "" || data.ControlPlane.SigningPrivateKey == "" {
		t.Fatalf("local vault identity = %#v", data.ControlPlane)
	}
	for _, path := range []string{application.paths.Vault, application.paths.LocalKey} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
}

func TestConfigureSelectsBetaControlPlane(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BEACON_HOME", home)
	application, err := New("v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	application.stdin = bytes.NewBufferString(testToken() + "\n")
	application.enroller = staticEnroller{}
	if err := application.configure(context.Background(), []string{
		"--local",
		"--name", "Beta",
		"--enrollment-token-stdin",
	}); err != nil {
		t.Fatal(err)
	}
	metadata, err := vault.ReadMetadata(application.paths.Vault)
	if err != nil {
		t.Fatal(err)
	}
	localKey, err := vault.OpenLocalKey(application.paths.LocalKey)
	if err != nil {
		t.Fatal(err)
	}
	defer localKey.Close()
	data, err := vault.NewStore(application.paths.Vault, metadata.Provider, metadata.KeyName, localKey).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.ControlPlane.URL != betaControlPlane {
		t.Fatalf("control plane = %q, want %q", data.ControlPlane.URL, betaControlPlane)
	}
}

func TestConfigureWithBlankTokenRetainsExistingIdentity(t *testing.T) {
	kms := &testKMS{}
	identity, err := enrollment.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault.bin")
	existing := vault.Data{ControlPlane: vault.ControlPlane{
		URL:               "https://old.example",
		BeaconID:          "bcn_bcdefghijklmnopqrstuvw",
		BeaconName:        "Production",
		SigningPrivateKey: identity.PrivateKey,
		SigningPublicKey:  identity.PublicKey,
	}}
	if err := vault.NewStore(path, vault.ProviderGoogleKMS, testKeyName, kms).Save(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	enroller := &testEnroller{kms: kms}
	application := &App{
		version: "v1.2.3",
		paths:   config.Paths{Vault: path},
		stdin:   bytes.NewReader(nil),
		newKeyWrapper: func(context.Context, vault.Provider, string, bool) (kmsWrapper, error) {
			return kms, nil
		},
		enroller:         enroller,
		generateIdentity: enrollment.GenerateIdentity,
	}
	arguments := []string{
		"--kms-key", testKeyName,
		"--name", "Production",
	}
	if err := application.configure(context.Background(), arguments); err != nil {
		t.Fatal(err)
	}
	if enroller.calls != 0 {
		t.Fatalf("blank-token reconfiguration enrolled %d times", enroller.calls)
	}
	data, err := vault.NewStore(path, vault.ProviderGoogleKMS, testKeyName, kms).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.ControlPlane.URL != betaControlPlane || data.ControlPlane.BeaconID != existing.ControlPlane.BeaconID ||
		data.ControlPlane.SigningPrivateKey != existing.ControlPlane.SigningPrivateKey {
		t.Fatalf("reconfigured identity = %#v", data.ControlPlane)
	}
}

func TestInvalidTokenFailsBeforeOpeningKMS(t *testing.T) {
	opened := false
	application := &App{
		version: "v1.2.3",
		paths:   config.Paths{Vault: filepath.Join(t.TempDir(), "vault.bin")},
		stdin:   bytes.NewBufferString("not-a-token\n"),
		newKeyWrapper: func(context.Context, vault.Provider, string, bool) (kmsWrapper, error) {
			opened = true
			return nil, errors.New("should not open")
		},
	}
	err := application.configure(context.Background(), []string{
		"--kms-key", testKeyName,
		"--name", "Production",
		"--enrollment-token-stdin",
	})
	if err == nil || opened {
		t.Fatalf("error=%v opened=%v, want validation error before KMS", err, opened)
	}
}

func testToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
}

type importKMS struct{}

func (importKMS) Wrap(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func (importKMS) Unwrap(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}

func (importKMS) Close() error { return nil }

func importTestApp(t *testing.T, input io.Reader, output io.Writer) (*App, string, importKMS) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.bin")
	wrapper := importKMS{}
	initial := vault.Empty()
	initial.Integrations["existing"] = map[string]string{"token": "keep-me"}
	if err := vault.NewStore(path, vault.ProviderGoogleKMS, testKeyName, wrapper).Save(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	return &App{
		paths:  config.Paths{Vault: path},
		stdin:  input,
		stdout: output,
		newKeyWrapper: func(context.Context, vault.Provider, string, bool) (kmsWrapper, error) {
			return wrapper, nil
		},
	}, path, wrapper
}

func TestCredentialImportMergesAtomicallyWithoutRenderingValues(t *testing.T) {
	const githubToken = "github-super-secret-value-4512"
	const googleKey = "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"
	payload, err := json.Marshal(credentialImport{Version: 1, Secrets: []credentialImportItem{
		{Integration: "github", Name: "token", Value: githubToken},
		{Integration: "github", Name: "org", Value: "iamly"},
		{Integration: "google", Name: "privateKey", Value: googleKey},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	application, path, wrapper := importTestApp(t, bytes.NewReader(payload), &output)
	if err := application.importSecrets(context.Background(), []string{"--stdin"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), githubToken) || strings.Contains(output.String(), googleKey) {
		t.Fatalf("import output exposed a credential: %q", output.String())
	}
	if !strings.Contains(output.String(), "3 encrypted credentials across 2 integrations") {
		t.Fatalf("unexpected import output: %q", output.String())
	}
	data, err := vault.NewStore(path, vault.ProviderGoogleKMS, testKeyName, wrapper).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.Integrations["existing"]["token"] != "keep-me" ||
		data.Integrations["github"]["token"] != githubToken ||
		data.Integrations["google"]["privateKey"] != googleKey {
		t.Fatal("import did not merge the complete credential bundle")
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, plaintext := range []string{githubToken, googleKey, "privateKey"} {
		if bytes.Contains(blob, []byte(plaintext)) {
			t.Fatalf("encrypted vault contains plaintext %q", plaintext)
		}
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("vault permissions after import = %v, %v", info, err)
	}
}

func TestCredentialImportRejectsInvalidPayloadWithoutWriting(t *testing.T) {
	cases := map[string]string{
		"unknown field":       `{"version":1,"secrets":[],"extra":true}`,
		"trailing JSON":       `{"version":1,"secrets":[{"integration":"slack","name":"userToken","value":"x"}]} {}`,
		"duplicate":           `{"version":1,"secrets":[{"integration":"slack","name":"userToken","value":"x"},{"integration":"slack","name":"userToken","value":"y"}]}`,
		"invalid integration": `{"version":1,"secrets":[{"integration":"Slack","name":"userToken","value":"x"}]}`,
		"invalid name":        `{"version":1,"secrets":[{"integration":"slack","name":"bad.name","value":"x"}]}`,
		"empty value":         `{"version":1,"secrets":[{"integration":"slack","name":"userToken","value":""}]}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			application, path, _ := importTestApp(t, strings.NewReader(input), io.Discard)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := application.importSecrets(context.Background(), []string{"--stdin"}); err == nil {
				t.Fatal("invalid import succeeded")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("invalid import modified the vault")
			}
		})
	}
}

func TestSecretListIsSortedAndNamesOnly(t *testing.T) {
	application, _, _ := importTestApp(t, strings.NewReader(`{"version":1,"secrets":[{"integration":"slack","name":"userToken","value":"slack-secret"},{"integration":"github","name":"token","value":"github-secret"}]}`), io.Discard)
	if err := application.importSecrets(context.Background(), []string{"--stdin"}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	application.stdout = &output
	if err := application.listSecrets(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "existing.token\ngithub.token\nslack.userToken\n"
	if output.String() != want {
		t.Fatalf("secret list = %q, want %q", output.String(), want)
	}
	if strings.Contains(output.String(), "slack-secret") || strings.Contains(output.String(), "github-secret") {
		t.Fatal("secret list exposed values")
	}
}

func TestConfigureStorageSelectors(t *testing.T) {
	tests := []struct {
		name             string
		arguments        []string
		provider         vault.Provider
		providerExplicit bool
		nonInteractive   bool
		wantError        bool
	}{
		{name: "new default stays interactive", arguments: nil},
		{name: "local", arguments: []string{"--local"}, provider: vault.ProviderLocal, providerExplicit: true},
		{name: "google", arguments: []string{"--google-kms"}, provider: vault.ProviderGoogleKMS, providerExplicit: true},
		{name: "aws", arguments: []string{"--aws-kms"}, provider: vault.ProviderAWSKMS, providerExplicit: true},
		{name: "retired development selector is rejected", arguments: []string{"--dev"}, wantError: true},
		{name: "legacy kms key infers google", arguments: []string{"--kms-key", testKeyName}, provider: vault.ProviderGoogleKMS, providerExplicit: true, nonInteractive: true},
		{name: "conflict", arguments: []string{"--local", "--aws-kms"}, wantError: true},
		{name: "customer URL rejected", arguments: []string{"--control-plane", "https://other.example"}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseConfigureOptions(test.arguments)
			if test.wantError {
				if err == nil {
					t.Fatal("conflicting selectors succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.provider != test.provider || got.providerExplicit != test.providerExplicit || got.nonInteractive != test.nonInteractive {
				t.Fatalf("options = %#v", got)
			}
		})
	}
}

func TestConfigureCanRewrapExistingVaultToLocalStorage(t *testing.T) {
	identity, err := enrollment.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vault.bin")
	wrapper := importKMS{}
	existing := vault.Data{ControlPlane: vault.ControlPlane{
		URL:               "https://old.example",
		BeaconID:          "bcn_bcdefghijklmnopqrstuvw",
		BeaconName:        "Production",
		SigningPrivateKey: identity.PrivateKey,
		SigningPublicKey:  identity.PublicKey,
	}}
	if err := vault.NewStore(path, vault.ProviderGoogleKMS, testKeyName, wrapper).Save(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	var opened []vault.Provider
	var localCreate bool
	application := &App{
		version: "v1.2.3",
		paths:   config.Paths{Vault: path, LocalKey: filepath.Join(filepath.Dir(path), vault.LocalKeyName)},
		stdin:   bytes.NewReader(nil),
		newKeyWrapper: func(_ context.Context, provider vault.Provider, _ string, create bool) (kmsWrapper, error) {
			opened = append(opened, provider)
			if provider == vault.ProviderLocal {
				localCreate = create
			}
			return wrapper, nil
		},
	}
	if err := application.configure(context.Background(), []string{
		"--local",
		"--name", "Production",
	}); err != nil {
		t.Fatal(err)
	}
	metadata, err := vault.ReadMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Provider != vault.ProviderLocal || metadata.KeyName != vault.LocalKeyName {
		t.Fatalf("metadata = %#v", metadata)
	}
	data, err := vault.NewStore(path, vault.ProviderLocal, vault.LocalKeyName, wrapper).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.ControlPlane.URL != betaControlPlane || data.ControlPlane.SigningPrivateKey != existing.ControlPlane.SigningPrivateKey {
		t.Fatalf("migrated identity = %#v", data.ControlPlane)
	}
	if len(opened) != 2 || opened[0] != vault.ProviderGoogleKMS || opened[1] != vault.ProviderLocal || !localCreate {
		t.Fatalf("opened providers = %#v, local create = %v", opened, localCreate)
	}
}
