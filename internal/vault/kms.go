package vault

import (
	"context"
	"fmt"
	"hash/crc32"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type KeyWrapper interface {
	Wrap(context.Context, string, []byte) ([]byte, error)
	Unwrap(context.Context, string, []byte) ([]byte, error)
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
