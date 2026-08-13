package vault

import (
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
	path    string
	keyName string
	wrapper KeyWrapper
}

type Metadata struct {
	Version  int
	Provider string
	KeyName  string
}

func ReadMetadata(path string) (Metadata, error) {
	blob, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Metadata{}, ErrNotFound
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("read vault: %w", err)
	}
	var file envelope
	if err := json.Unmarshal(blob, &file); err != nil {
		return Metadata{}, errors.New("vault format is invalid")
	}
	if file.Version != formatVersion || file.Provider != "gcp-kms" || file.KeyName == "" {
		return Metadata{}, errors.New("vault format or key provider is unsupported")
	}
	return Metadata{Version: file.Version, Provider: file.Provider, KeyName: file.KeyName}, nil
}

func NewStore(path, keyName string, wrapper KeyWrapper) *Store {
	return &Store{path: path, keyName: keyName, wrapper: wrapper}
}

func (s *Store) Save(ctx context.Context, data Data) error {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}
	defer wipe(plaintext)

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

	metadata := authenticatedMetadata(formatVersion, "gcp-kms", s.keyName)
	file := envelope{
		Version: formatVersion, Provider: "gcp-kms", KeyName: s.keyName,
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
	blob, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Data{}, ErrNotFound
	}
	if err != nil {
		return Data{}, fmt.Errorf("read vault: %w", err)
	}
	var file envelope
	if err := json.Unmarshal(blob, &file); err != nil {
		return Data{}, errors.New("vault format is invalid")
	}
	if file.Version != formatVersion || file.Provider != "gcp-kms" || file.KeyName == "" {
		return Data{}, errors.New("vault format or key provider is unsupported")
	}
	dek, err := s.wrapper.Unwrap(ctx, file.KeyName, file.WrappedDEK)
	if err != nil {
		return Data{}, err
	}
	defer wipe(dek)
	cipher, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return Data{}, errors.New("GCP KMS returned an invalid vault key")
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

func authenticatedMetadata(version int, provider, keyName string) []byte {
	return []byte(fmt.Sprintf("reviam-beacon-vault:%d:%s:%s", version, provider, keyName))
}

func atomicWrite(path string, blob []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vault-*")
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
	return nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
