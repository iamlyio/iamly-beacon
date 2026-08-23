package releasetrust

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestVerifyAcceptsTrustedSignatureAndRejectsTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checksums := []byte(strings.Repeat("a", 64) + "  beacon.tar.gz\n")
	envelope, err := Sign("v2.3.0", checksums, map[string]ed25519.PrivateKey{"root": privateKey})
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{"root": publicKey}
	if err := Verify("v2.3.0", checksums, envelope, trusted); err != nil {
		t.Fatal(err)
	}
	if err := Verify("v2.3.0", append(append([]byte{}, checksums...), 'x'), envelope, trusted); err == nil {
		t.Fatal("tampered checksums were accepted")
	}
	if err := Verify("v2.3.1", checksums, envelope, trusted); err == nil {
		t.Fatal("signature replay under another version was accepted")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongPublicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	envelope, err := Sign("v2.3.0", []byte("checksums"), map[string]ed25519.PrivateKey{"root": privateKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify("v2.3.0", []byte("checksums"), envelope, map[string]ed25519.PublicKey{"root": wrongPublicKey}); err == nil {
		t.Fatal("signature from a wrong key was accepted")
	}
}
