package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

type memoryWrapper struct{ key byte }

func (m memoryWrapper) Wrap(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	result := append([]byte(nil), plaintext...)
	for index := range result {
		result[index] ^= m.key
	}
	return result, nil
}

func (m memoryWrapper) Unwrap(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	return m.Wrap(ctx, keyName, ciphertext)
}

func TestVaultRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.bin")
	store := NewStore(path, ProviderGoogleKMS, "projects/acme/locations/global/keyRings/iamly/cryptoKeys/beacon", memoryWrapper{key: 0x5a})
	want := Data{
		ControlPlane: ControlPlane{
			URL:               "https://app.iamly.example",
			BeaconID:          "beacon_01",
			BeaconName:        "Production",
			SigningPrivateKey: "private-signing-key",
			SigningPublicKey:  "public-signing-key",
		},
		Integrations: map[string]map[string]string{"github": {"token": "github-secret"}},
	}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("private-signing-key"), []byte("github-secret")} {
		if bytes.Contains(blob, secret) {
			t.Fatalf("encrypted vault contains plaintext %q", secret)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode = %o, want 600", info.Mode().Perm())
	}
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.ControlPlane.SigningPrivateKey != want.ControlPlane.SigningPrivateKey {
		t.Fatal("signing private key did not round trip")
	}
	if got.Integrations["github"]["token"] != "github-secret" {
		t.Fatal("integration secret did not round trip")
	}
}

func TestEverySaveUsesFreshDEKAndNonce(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first.vault")
	second := filepath.Join(directory, "second.vault")
	wrapper := memoryWrapper{key: 0xa5}
	data := Empty()
	if err := NewStore(first, ProviderGoogleKMS, "projects/p/locations/l/keyRings/r/cryptoKeys/k", wrapper).Save(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(second, ProviderGoogleKMS, "projects/p/locations/l/keyRings/r/cryptoKeys/k", wrapper).Save(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(first)
	b, _ := os.ReadFile(second)
	if bytes.Equal(a, b) {
		t.Fatal("two vault writes produced identical envelopes")
	}
}

func TestTamperingIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.bin")
	store := NewStore(path, ProviderGoogleKMS, "projects/p/locations/l/keyRings/r/cryptoKeys/k", memoryWrapper{key: 7})
	if err := store.Save(context.Background(), Empty()); err != nil {
		t.Fatal(err)
	}
	blob, _ := os.ReadFile(path)
	if _, err := rand.Read(blob[len(blob)-8:]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil {
		t.Fatal("Load() accepted a modified vault")
	}
}

func TestMalformedNonceIsRejectedWithoutPanicking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.bin")
	store := NewStore(path, ProviderGoogleKMS, "projects/p/locations/l/keyRings/r/cryptoKeys/k", memoryWrapper{key: 7})
	if err := store.Save(context.Background(), Empty()); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file envelope
	if err := json.Unmarshal(blob, &file); err != nil {
		t.Fatal(err)
	}
	file.Nonce = make([]byte, chacha20poly1305.NonceSizeX-1)
	blob, err = json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil {
		t.Fatal("Load() accepted an invalid nonce")
	}
}

func TestSaveSecuresExistingVaultDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "beacon")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "vault.bin")
	if err := NewStore(path, ProviderGoogleKMS, "projects/p/locations/l/keyRings/r/cryptoKeys/k", memoryWrapper{key: 7}).Save(context.Background(), Empty()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("vault directory mode=%o, want 700", info.Mode().Perm())
	}
}

func TestKMSSelfTestWrapsAndUnwraps(t *testing.T) {
	if err := SelfTest(context.Background(), "key", memoryWrapper{key: 0x5a}); err != nil {
		t.Fatal(err)
	}
}

func TestVaultProviderIsAuthenticatedAndMustMatchWrapperSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.bin")
	keyName := "projects/p/locations/l/keyRings/r/cryptoKeys/k"
	wrapper := memoryWrapper{key: 0x5a}
	if err := NewStore(path, ProviderGoogleKMS, keyName, wrapper).Save(context.Background(), Empty()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path, ProviderAWSKMS, keyName, wrapper).Load(context.Background()); err == nil {
		t.Fatal("vault opened with a different provider")
	}
	metadata, err := ReadMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Provider != ProviderGoogleKMS {
		t.Fatalf("provider = %q", metadata.Provider)
	}
}
