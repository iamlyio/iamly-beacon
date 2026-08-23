package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSigningKeysRequiresFingerprintKeyID(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(publicKey)
	keyID := hex.EncodeToString(fingerprint[:])[:16]
	encodedKey := base64.StdEncoding.EncodeToString(der)
	if _, err := signingKeys(fmt.Sprintf(`{%q:%q}`, keyID, encodedKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := signingKeys(fmt.Sprintf(`{"wrong-key-id":%q}`, encodedKey)); err == nil {
		t.Fatal("mismatched release signing key ID was accepted")
	}
}
