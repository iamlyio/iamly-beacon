package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocalKeyCreateWrapAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "beacon", LocalKeyName)
	key, err := OpenOrCreateLocalKey(path)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte{0x42}, 32)
	wrapped, err := key.Wrap(context.Background(), LocalKeyName, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, plaintext) {
		t.Fatal("wrapped data key contains its plaintext")
	}
	if err := key.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenLocalKey(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.Unwrap(context.Background(), LocalKeyName, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("local key did not unwrap the original data key")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("local key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestOpenLocalKeyRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), LocalKeyName)
	if err := os.WriteFile(path, make([]byte, localKeySize), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocalKey(path); err == nil {
		t.Fatal("OpenLocalKey accepted a group/world-readable key")
	}
}

func TestOpenLocalKeyDoesNotCreateMissingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), LocalKeyName)
	if _, err := OpenLocalKey(path); err == nil {
		t.Fatal("OpenLocalKey accepted a missing key")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing key was created: %v", err)
	}
}
