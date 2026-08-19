package vault

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	LocalKeyName = "local.key"
	localKeySize = chacha20poly1305.KeySize
)

var localWrapMetadata = []byte("iamly-beacon-local-key-wrap:v1")

type LocalKey struct {
	key []byte
}

func OpenLocalKey(path string) (*LocalKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("open local vault key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("local vault key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("local vault key permissions are %o; require 0600", info.Mode().Perm())
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read local vault key: %w", err)
	}
	if len(key) != localKeySize {
		wipe(key)
		return nil, errors.New("local vault key is invalid")
	}
	return &LocalKey{key: key}, nil
}

func OpenOrCreateLocalKey(path string) (*LocalKey, error) {
	key, err := OpenLocalKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := createLocalKey(path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return OpenLocalKey(path)
		}
		return nil, err
	}
	return OpenLocalKey(path)
}

func createLocalKey(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create local vault key directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("secure local vault key directory: %w", err)
	}
	key := make([]byte, localKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generate local vault key: %w", err)
	}
	defer wipe(key)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create local vault key: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(key); err != nil {
		file.Close()
		return fmt.Errorf("write local vault key: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync local vault key: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close local vault key: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open local vault key directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync local vault key directory: %w", err)
	}
	complete = true
	return nil
}

func (k *LocalKey) Wrap(_ context.Context, keyName string, plaintext []byte) ([]byte, error) {
	if keyName != LocalKeyName {
		return nil, errors.New("local vault key metadata is invalid")
	}
	cipher, err := chacha20poly1305.NewX(k.key)
	if err != nil {
		return nil, errors.New("local vault key is invalid")
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate local key-wrap nonce: %w", err)
	}
	return append(nonce, cipher.Seal(nil, nonce, plaintext, localWrapMetadata)...), nil
}

func (k *LocalKey) Unwrap(_ context.Context, keyName string, ciphertext []byte) ([]byte, error) {
	if keyName != LocalKeyName {
		return nil, errors.New("local vault key metadata is invalid")
	}
	if len(ciphertext) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, errors.New("locally wrapped vault key is invalid")
	}
	cipher, err := chacha20poly1305.NewX(k.key)
	if err != nil {
		return nil, errors.New("local vault key is invalid")
	}
	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	plaintext, err := cipher.Open(nil, nonce, ciphertext[chacha20poly1305.NonceSizeX:], localWrapMetadata)
	if err != nil {
		return nil, errors.New("local vault key authentication failed")
	}
	return plaintext, nil
}

func (k *LocalKey) Close() error {
	wipe(k.key)
	k.key = nil
	return nil
}
