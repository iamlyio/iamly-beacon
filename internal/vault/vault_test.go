package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
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
	store := NewStore(path, "projects/acme/locations/global/keyRings/reviam/cryptoKeys/beacon", memoryWrapper{key: 0x5a})
	want := Data{
		ControlPlane: ControlPlane{URL: "https://app.reviam.example", BeaconID: "beacon_01", BeaconToken: "enrollment-secret-value"},
		Integrations: map[string]map[string]string{"github": {"token": "github-secret"}},
	}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("enrollment-secret-value"), []byte("github-secret")} {
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
	if got.ControlPlane.BeaconToken != want.ControlPlane.BeaconToken {
		t.Fatal("control-plane secret did not round trip")
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
	if err := NewStore(first, "projects/p/locations/l/keyRings/r/cryptoKeys/k", wrapper).Save(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	if err := NewStore(second, "projects/p/locations/l/keyRings/r/cryptoKeys/k", wrapper).Save(context.Background(), data); err != nil {
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
	store := NewStore(path, "projects/p/locations/l/keyRings/r/cryptoKeys/k", memoryWrapper{key: 7})
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
