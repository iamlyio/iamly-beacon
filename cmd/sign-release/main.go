package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/iamlyio/iamly-beacon/internal/releasetrust"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 4 {
		return errors.New("use sign-release VERSION CHECKSUMS OUTPUT")
	}
	checksums, err := os.ReadFile(os.Args[2])
	if err != nil {
		return errors.New("read release checksums")
	}
	keys, err := signingKeys(os.Getenv("BEACON_RELEASE_SIGNING_KEYS"))
	if err != nil {
		return err
	}
	envelope, err := releasetrust.Sign(os.Args[1], checksums, keys)
	if err != nil {
		return err
	}
	if err := os.WriteFile(os.Args[3], append(envelope, '\n'), 0o600); err != nil {
		return errors.New("write release signature manifest")
	}
	return nil
}

func signingKeys(encoded string) (map[string]ed25519.PrivateKey, error) {
	var values map[string]string
	if encoded == "" || json.Unmarshal([]byte(encoded), &values) != nil || len(values) == 0 {
		return nil, errors.New("BEACON_RELEASE_SIGNING_KEYS must be a JSON object of key IDs to base64 PKCS#8 keys")
	}
	keys := make(map[string]ed25519.PrivateKey, len(values))
	for keyID, value := range values {
		der, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, errors.New("decode release signing key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		privateKey, ok := parsed.(ed25519.PrivateKey)
		if err != nil || !ok {
			return nil, errors.New("parse Ed25519 release signing key")
		}
		fingerprint := sha256.Sum256(privateKey.Public().(ed25519.PublicKey))
		if keyID != hex.EncodeToString(fingerprint[:])[:16] {
			return nil, errors.New("release signing key ID does not match its public-key fingerprint")
		}
		keys[keyID] = privateKey
	}
	return keys, nil
}
