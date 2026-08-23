package releasetrust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
)

const messageDomain = "iamly-beacon-release-manifest-v1"

type Envelope struct {
	Signatures []Signature `json:"signatures"`
}

type Signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func Message(version string, checksums []byte) []byte {
	message := make([]byte, 0, len(messageDomain)+len(version)+len(checksums)+2)
	message = append(message, messageDomain...)
	message = append(message, '\n')
	message = append(message, version...)
	message = append(message, '\n')
	message = append(message, checksums...)
	return message
}

func Sign(version string, checksums []byte, keys map[string]ed25519.PrivateKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("no release signing keys were provided")
	}
	message := Message(version, checksums)
	envelope := Envelope{Signatures: make([]Signature, 0, len(keys))}
	keyIDs := make([]string, 0, len(keys))
	for keyID := range keys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	for _, keyID := range keyIDs {
		privateKey := keys[keyID]
		if keyID == "" || len(privateKey) != ed25519.PrivateKeySize {
			return nil, errors.New("release signing key is invalid")
		}
		envelope.Signatures = append(envelope.Signatures, Signature{
			KeyID:     keyID,
			Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, message)),
		})
	}
	return json.MarshalIndent(envelope, "", "  ")
}

func Verify(version string, checksums, encodedEnvelope []byte, trustedKeys map[string]ed25519.PublicKey) error {
	var envelope Envelope
	if err := json.Unmarshal(encodedEnvelope, &envelope); err != nil || len(envelope.Signatures) == 0 {
		return errors.New("release signature manifest is invalid")
	}
	message := Message(version, checksums)
	seen := make(map[string]struct{}, len(envelope.Signatures))
	for _, candidate := range envelope.Signatures {
		if _, duplicate := seen[candidate.KeyID]; duplicate {
			return errors.New("release signature manifest contains a duplicate key")
		}
		seen[candidate.KeyID] = struct{}{}
		publicKey, trusted := trustedKeys[candidate.KeyID]
		if !trusted {
			continue
		}
		signature, err := base64.RawStdEncoding.DecodeString(candidate.Signature)
		if err == nil && ed25519.Verify(publicKey, message, signature) {
			return nil
		}
	}
	return errors.New("release manifest is not signed by a trusted IAMly release key")
}
