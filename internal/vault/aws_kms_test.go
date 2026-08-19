package vault

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeAWSKMSClient struct {
	testing *testing.T
	keyName string
}

func (f fakeAWSKMSClient) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	f.assertRequest(aws.ToString(input.KeyId), input.EncryptionAlgorithm, input.EncryptionContext)
	return &kms.EncryptOutput{CiphertextBlob: append([]byte("wrapped:"), input.Plaintext...)}, nil
}

func (f fakeAWSKMSClient) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	f.assertRequest(aws.ToString(input.KeyId), input.EncryptionAlgorithm, input.EncryptionContext)
	if !bytes.HasPrefix(input.CiphertextBlob, []byte("wrapped:")) {
		return nil, errors.New("unexpected ciphertext")
	}
	return &kms.DecryptOutput{Plaintext: append([]byte(nil), input.CiphertextBlob[len("wrapped:"):]...)}, nil
}

func (f fakeAWSKMSClient) assertRequest(keyName string, algorithm types.EncryptionAlgorithmSpec, encryptionContext map[string]string) {
	f.testing.Helper()
	if keyName != f.keyName {
		f.testing.Fatalf("key = %q, want %q", keyName, f.keyName)
	}
	if algorithm != types.EncryptionAlgorithmSpecSymmetricDefault {
		f.testing.Fatalf("algorithm = %q", algorithm)
	}
	if encryptionContext[awsEncryptionContextKey] != f.keyName {
		f.testing.Fatalf("encryption context = %#v", encryptionContext)
	}
}

func TestAWSKMSWrapAndUnwrapBindKeyAndContext(t *testing.T) {
	const keyName = "arn:aws:kms:eu-west-3:123456789012:key/11111111-2222-3333-4444-555555555555"
	wrapper := &AWSKMS{client: fakeAWSKMSClient{testing: t, keyName: keyName}}
	plaintext := bytes.Repeat([]byte{0x23}, 32)
	wrapped, err := wrapper.Wrap(context.Background(), keyName, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := wrapper.Unwrap(context.Background(), keyName, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("AWS KMS wrapper did not round trip the data key")
	}
}

func TestAWSRegionFromKeyARN(t *testing.T) {
	if got := awsRegionFromKeyARN("arn:aws:kms:eu-west-3:123456789012:key/id"); got != "eu-west-3" {
		t.Fatalf("region = %q", got)
	}
	if got := awsRegionFromKeyARN("alias/beacon"); got != "" {
		t.Fatalf("alias region = %q, want empty", got)
	}
}
