package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

const formatVersion = 1

type Provider string

const (
	ProviderLocal     Provider = "local"
	ProviderGoogleKMS Provider = "gcp-kms"
	ProviderAWSKMS    Provider = "aws-kms"
)

const (
	maxVaultFileBytes      = 128 << 20
	maxVaultPlaintextBytes = 80 << 20
	maxWrappedKeyBytes     = 64 << 10
)

var ErrNotFound = errors.New("vault has not been created")

type envelope struct {
	Version    int    `json:"version"`
	Provider   string `json:"provider"`
	KeyName    string `json:"key_name"`
	WrappedDEK []byte `json:"wrapped_dek"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type Store struct {
	path     string
	provider Provider
	keyName  string
	wrapper  KeyWrapper
}

type Metadata struct {
	Version  int
	Provider Provider
	KeyName  string
}

func ReadMetadata(path string) (Metadata, error) {
	file, err := readEnvelope(path)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{Version: file.Version, Provider: Provider(file.Provider), KeyName: file.KeyName}, nil
}

func NewStore(path string, provider Provider, keyName string, wrapper KeyWrapper) *Store {
	return &Store{path: path, provider: provider, keyName: keyName, wrapper: wrapper}
}

func (s *Store) Save(ctx context.Context, data Data) error {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	defer wipe(plaintext)
	if len(plaintext) > maxVaultPlaintextBytes {
		return errors.New("vault payload exceeds the 80 MiB limit")
	}

	dek := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return fmt.Errorf("generate vault key: %w", err)
	}
	defer wipe(dek)

	cipher, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return fmt.Errorf("create vault cipher: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate vault nonce: %w", err)
	}
	wrappedDEK, err := s.wrapper.Wrap(ctx, s.keyName, dek)
	if err != nil {
		return err
	}

	metadata := authenticatedMetadata(formatVersion, string(s.provider), s.keyName)
	file := envelope{
		Version: formatVersion, Provider: string(s.provider), KeyName: s.keyName,
		WrappedDEK: wrappedDEK, Nonce: nonce,
		Ciphertext: cipher.Seal(nil, nonce, plaintext, metadata),
	}
	blob, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("encode encrypted vault: %w", err)
	}
	return atomicWrite(s.path, blob)
}

func (s *Store) Load(ctx context.Context) (Data, error) {
	file, err := readEnvelope(s.path)
	if err != nil {
		return Data{}, err
	}
	if Provider(file.Provider) != s.provider || file.KeyName != s.keyName {
		return Data{}, errors.New("vault provider or key metadata changed while opening the vault")
	}
	dek, err := s.wrapper.Unwrap(ctx, file.KeyName, file.WrappedDEK)
	if err != nil {
		return Data{}, err
	}
	defer wipe(dek)
	cipher, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return Data{}, errors.New("vault key provider returned an invalid data key")
	}
	metadata := authenticatedMetadata(file.Version, file.Provider, file.KeyName)
	plaintext, err := cipher.Open(nil, file.Nonce, file.Ciphertext, metadata)
	if err != nil {
		return Data{}, errors.New("vault authentication failed")
	}
	defer wipe(plaintext)
	data := Empty()
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return Data{}, errors.New("vault payload is invalid")
	}
	return data, nil
}

func readEnvelope(path string) (envelope, error) {
	input, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return envelope{}, ErrNotFound
	}
	if err != nil {
		return envelope{}, fmt.Errorf("read vault: %w", err)
	}
	defer input.Close()

	blob, err := io.ReadAll(io.LimitReader(input, maxVaultFileBytes+1))
	if err != nil {
		return envelope{}, fmt.Errorf("read vault: %w", err)
	}
	if len(blob) > maxVaultFileBytes {
		return envelope{}, errors.New("vault file exceeds the 128 MiB limit")
	}
	var file envelope
	decoder := json.NewDecoder(bytes.NewReader(blob))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return envelope{}, errors.New("vault format is invalid")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return envelope{}, errors.New("vault format is invalid")
	}
	provider := Provider(file.Provider)
	if file.Version != formatVersion ||
		(provider != ProviderLocal && provider != ProviderGoogleKMS && provider != ProviderAWSKMS) ||
		file.KeyName == "" {
		return envelope{}, errors.New("vault format or key provider is unsupported")
	}
	if len(file.WrappedDEK) == 0 || len(file.WrappedDEK) > maxWrappedKeyBytes ||
		len(file.Nonce) != chacha20poly1305.NonceSizeX ||
		len(file.Ciphertext) < chacha20poly1305.Overhead || len(file.Ciphertext) > maxVaultPlaintextBytes+chacha20poly1305.Overhead {
		return envelope{}, errors.New("vault cryptographic envelope is invalid")
	}
	return file, nil
}

func authenticatedMetadata(version int, provider, keyName string) []byte {
	return []byte(fmt.Sprintf("iamly-beacon-vault:%d:%s:%s", version, provider, keyName))
}

func atomicWrite(path string, blob []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure vault directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".vault-*")
	if err != nil {
		return fmt.Errorf("create temporary vault: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(blob); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace vault: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open vault directory for sync: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync vault directory: %w", err)
	}
	return nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
