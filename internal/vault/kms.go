package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type KeyWrapper interface {
	Wrap(context.Context, string, []byte) ([]byte, error)
	Unwrap(context.Context, string, []byte) ([]byte, error)
}

// SelfTest verifies that the configured key can both wrap and unwrap data
// before a single-use enrollment token is sent to the control plane.
func SelfTest(ctx context.Context, keyName string, wrapper KeyWrapper) error {
	probe := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, probe); err != nil {
		return fmt.Errorf("generate GCP KMS self-test value: %w", err)
	}
	defer wipe(probe)

	wrapped, err := wrapper.Wrap(ctx, keyName, probe)
	if err != nil {
		return fmt.Errorf("GCP KMS self-test: %w", err)
	}
	defer wipe(wrapped)
	unwrapped, err := wrapper.Unwrap(ctx, keyName, wrapped)
	if err != nil {
		return fmt.Errorf("GCP KMS self-test: %w", err)
	}
	defer wipe(unwrapped)
	if !bytes.Equal(probe, unwrapped) {
		return fmt.Errorf("GCP KMS self-test: unwrapped value does not match")
	}
	return nil
}

type GCPKMS struct {
	client *kms.KeyManagementClient
}

func NewGCPKMS(ctx context.Context) (*GCPKMS, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect to GCP Cloud KMS: %w", err)
	}
	return &GCPKMS{client: client}, nil
}

func (k *GCPKMS) Close() error { return k.client.Close() }

func (k *GCPKMS) Wrap(ctx context.Context, keyName string, plaintext []byte) ([]byte, error) {
	response, err := k.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name: keyName, Plaintext: plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32.Checksum(plaintext, crc32.MakeTable(crc32.Castagnoli)))),
	})
	if err != nil {
		return nil, fmt.Errorf("wrap vault key with GCP KMS: %w", err)
	}
	if !response.VerifiedPlaintextCrc32C || response.CiphertextCrc32C == nil ||
		uint32(response.CiphertextCrc32C.Value) != crc32.Checksum(response.Ciphertext, crc32.MakeTable(crc32.Castagnoli)) {
		return nil, fmt.Errorf("wrap vault key with GCP KMS: response integrity check failed")
	}
	return response.Ciphertext, nil
}

func (k *GCPKMS) Unwrap(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	response, err := k.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name: keyName, Ciphertext: ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(crc32.Checksum(ciphertext, crc32.MakeTable(crc32.Castagnoli)))),
	})
	if err != nil {
		return nil, fmt.Errorf("unwrap vault key with GCP KMS: %w", err)
	}
	if response.PlaintextCrc32C == nil ||
		uint32(response.PlaintextCrc32C.Value) != crc32.Checksum(response.Plaintext, crc32.MakeTable(crc32.Castagnoli)) {
		return nil, fmt.Errorf("unwrap vault key with GCP KMS: response integrity check failed")
	}
	return response.Plaintext, nil
}
