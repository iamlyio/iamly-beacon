package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

const awsEncryptionContextKey = "iamly.io:beacon-vault"

type awsKMSClient interface {
	Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type AWSKMS struct {
	client awsKMSClient
}

func NewAWSKMS(ctx context.Context, keyName string) (*AWSKMS, error) {
	options := []func(*awsconfig.LoadOptions) error{}
	if region := awsRegionFromKeyARN(keyName); region != "" {
		options = append(options, awsconfig.WithRegion(region))
	}
	configuration, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	return &AWSKMS{client: kms.NewFromConfig(configuration)}, nil
}

func awsRegionFromKeyARN(keyName string) string {
	parts := strings.Split(keyName, ":")
	if len(parts) == 6 && parts[0] == "arn" && parts[2] == "kms" {
		return parts[3]
	}
	return ""
}

func awsEncryptionContext(keyName string) map[string]string {
	return map[string]string{awsEncryptionContextKey: keyName}
}

func (k *AWSKMS) Wrap(ctx context.Context, keyName string, plaintext []byte) ([]byte, error) {
	response, err := k.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:               aws.String(keyName),
		Plaintext:           plaintext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   awsEncryptionContext(keyName),
	})
	if err != nil {
		return nil, fmt.Errorf("wrap vault key with AWS KMS: %w", err)
	}
	if len(response.CiphertextBlob) == 0 {
		return nil, fmt.Errorf("wrap vault key with AWS KMS: empty ciphertext")
	}
	return response.CiphertextBlob, nil
}

func (k *AWSKMS) Unwrap(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	response, err := k.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:               aws.String(keyName),
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		EncryptionContext:   awsEncryptionContext(keyName),
	})
	if err != nil {
		return nil, fmt.Errorf("unwrap vault key with AWS KMS: %w", err)
	}
	if len(response.Plaintext) == 0 {
		return nil, fmt.Errorf("unwrap vault key with AWS KMS: empty plaintext")
	}
	return response.Plaintext, nil
}

func (k *AWSKMS) Close() error { return nil }
