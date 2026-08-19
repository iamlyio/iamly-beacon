package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePathsUsesIamlyHomeForNewInstallations(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "config"))
	t.Setenv("BEACON_HOME", "")

	configHome, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ResolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(configHome, "iamly", "beacon")
	if paths.Home != want {
		t.Fatalf("Home = %q, want %q", paths.Home, want)
	}
}
