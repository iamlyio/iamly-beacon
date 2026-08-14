package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Paths struct {
	Home  string
	Vault string
}

func ResolvePaths() (Paths, error) {
	home := os.Getenv("BEACON_HOME")
	if home == "" {
		configHome, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user config directory: %w", err)
		}
		home = filepath.Join(configHome, "iamly", "beacon")
		legacyHome := filepath.Join(configHome, "reviam", "beacon")
		if _, currentErr := os.Stat(filepath.Join(home, "vault.bin")); os.IsNotExist(currentErr) {
			if _, legacyErr := os.Stat(filepath.Join(legacyHome, "vault.bin")); legacyErr == nil {
				home = legacyHome
			}
		}
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve Beacon home: %w", err)
	}
	return Paths{Home: abs, Vault: filepath.Join(abs, "vault.bin")}, nil
}
