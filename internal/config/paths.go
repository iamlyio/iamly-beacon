package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Paths struct {
	Home     string
	Vault    string
	LocalKey string
}

func ResolvePaths() (Paths, error) {
	home := os.Getenv("BEACON_HOME")
	if home == "" {
		configHome, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user config directory: %w", err)
		}
		home = filepath.Join(configHome, "iamly", "beacon")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return Paths{}, fmt.Errorf("resolve Beacon home: %w", err)
	}
	return Paths{
		Home:     abs,
		Vault:    filepath.Join(abs, "vault.bin"),
		LocalKey: filepath.Join(abs, "local.key"),
	}, nil
}
