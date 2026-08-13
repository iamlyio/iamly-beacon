package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/reviam/beacon/internal/config"
	"github.com/reviam/beacon/internal/tui"
	"github.com/reviam/beacon/internal/vault"
)

var keyNamePattern = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)

type App struct {
	version string
	paths   config.Paths
}

func New(version string) (*App, error) {
	paths, err := config.ResolvePaths()
	if err != nil {
		return nil, err
	}
	return &App{version: version, paths: paths}, nil
}

func (a *App) Execute(ctx context.Context, arguments []string) error {
	if len(arguments) == 0 {
		action, err := tui.Select(a.version)
		if err != nil {
			return err
		}
		return a.execute(ctx, action)
	}
	switch arguments[0] {
	case "configure":
		return a.configure(ctx)
	case "secret":
		if len(arguments) < 2 {
			return errors.New("use beacon secret set or beacon secret list")
		}
		switch arguments[1] {
		case "set":
			return a.storeSecret(ctx)
		case "list":
			return a.listSecrets(ctx)
		default:
			return errors.New("use beacon secret set or beacon secret list")
		}
	case "status":
		return a.status(ctx)
	case "run":
		return a.run(ctx)
	case "version", "--version", "-v":
		fmt.Printf("Beacon %s\n", a.version)
		return nil
	case "help", "--help", "-h":
		printHelp()
		return nil
	default:
		return fmt.Errorf("unknown command %q; run beacon help", arguments[0])
	}
}

func (a *App) execute(ctx context.Context, action tui.Action) error {
	switch action {
	case tui.Configure:
		return a.configure(ctx)
	case tui.Secrets:
		return a.storeSecret(ctx)
	case tui.Status:
		return a.status(ctx)
	case tui.Run:
		return a.run(ctx)
	default:
		return nil
	}
}

func (a *App) storeSecret(ctx context.Context) error {
	metadata, data, kms, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()

	secret, saved, err := tui.Secret()
	if err != nil || !saved {
		return err
	}
	namePattern := regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	if !namePattern.MatchString(secret.Integration) || !namePattern.MatchString(secret.Name) {
		return errors.New("integration and secret names may contain lowercase letters, numbers, hyphens, and underscores")
	}
	if secret.Value == "" {
		return errors.New("secret value is required")
	}
	if data.Integrations == nil {
		data.Integrations = make(map[string]map[string]string)
	}
	if data.Integrations[secret.Integration] == nil {
		data.Integrations[secret.Integration] = make(map[string]string)
	}
	data.Integrations[secret.Integration][secret.Name] = secret.Value
	if err := vault.NewStore(a.paths.Vault, metadata.KeyName, kms).Save(ctx, data); err != nil {
		return err
	}
	fmt.Printf("✓ Stored %s.%s in the encrypted local vault\n", secret.Integration, secret.Name)
	return nil
}

func (a *App) listSecrets(ctx context.Context) error {
	_, data, kms, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()
	if len(data.Integrations) == 0 {
		fmt.Println("No integration secrets configured.")
		return nil
	}
	for integration, values := range data.Integrations {
		for name := range values {
			fmt.Printf("%s.%s\n", integration, name)
		}
	}
	return nil
}

func (a *App) openVault(ctx context.Context) (vault.Metadata, vault.Data, *vault.GCPKMS, error) {
	metadata, err := vault.ReadMetadata(a.paths.Vault)
	if err != nil {
		return vault.Metadata{}, vault.Data{}, nil, err
	}
	kms, err := vault.NewGCPKMS(ctx)
	if err != nil {
		return vault.Metadata{}, vault.Data{}, nil, err
	}
	data, err := vault.NewStore(a.paths.Vault, metadata.KeyName, kms).Load(ctx)
	if err != nil {
		kms.Close()
		return vault.Metadata{}, vault.Data{}, nil, err
	}
	return metadata, data, kms, nil
}

func (a *App) configure(ctx context.Context) error {
	initial := tui.SetupResult{Data: vault.Empty()}
	metadata, err := vault.ReadMetadata(a.paths.Vault)
	if err == nil {
		initial.KeyName = metadata.KeyName
		kms, openErr := vault.NewGCPKMS(ctx)
		if openErr != nil {
			return openErr
		}
		defer kms.Close()
		initial.Data, err = vault.NewStore(a.paths.Vault, metadata.KeyName, kms).Load(ctx)
		if err != nil {
			return err
		}
	} else if !errors.Is(err, vault.ErrNotFound) {
		return err
	}

	result, saved, err := tui.Setup(initial)
	if err != nil || !saved {
		return err
	}
	if err := validateSetup(result); err != nil {
		return err
	}

	kms, err := vault.NewGCPKMS(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()
	if err := vault.NewStore(a.paths.Vault, result.KeyName, kms).Save(ctx, result.Data); err != nil {
		return err
	}
	fmt.Printf("✓ Beacon configuration encrypted at %s\n", a.paths.Vault)
	return nil
}

func (a *App) status(ctx context.Context) error {
	metadata, err := vault.ReadMetadata(a.paths.Vault)
	if err != nil {
		return err
	}
	kms, err := vault.NewGCPKMS(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()
	data, err := vault.NewStore(a.paths.Vault, metadata.KeyName, kms).Load(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Beacon status\n  Control plane: %s\n  Beacon ID:     %s\n  Vault:         encrypted · GCP KMS\n  Integrations:  %d configured\n", data.ControlPlane.URL, data.ControlPlane.BeaconID, len(data.Integrations))
	return nil
}

func (a *App) run(ctx context.Context) error {
	if _, err := os.Stat(a.paths.Vault); errors.Is(err, os.ErrNotExist) {
		return errors.New("Beacon is not configured; run beacon configure")
	}
	return errors.New("collector transport is the next milestone; the GCP KMS vault is ready")
}

func validateSetup(result tui.SetupResult) error {
	if !keyNamePattern.MatchString(result.KeyName) {
		return errors.New("GCP KMS key must use projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}")
	}
	parsed, err := url.ParseRequestURI(result.Data.ControlPlane.URL)
	if err != nil || parsed.Host == "" {
		return errors.New("Reviam control-plane URL must be absolute")
	}
	if parsed.Scheme != "https" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" {
		return errors.New("Reviam control-plane URL must use HTTPS")
	}
	if strings.TrimSpace(result.Data.ControlPlane.BeaconID) == "" {
		return errors.New("Beacon ID is required")
	}
	if len(result.Data.ControlPlane.BeaconToken) < 32 {
		return errors.New("enrollment token must contain at least 32 characters")
	}
	return nil
}

func printHelp() {
	fmt.Print(`Beacon — Reviam's customer-hosted collector

Usage:
  beacon                 Open the terminal interface
  beacon configure       Configure GCP KMS and the encrypted local vault
  beacon secret set      Enter and encrypt an integration secret
  beacon secret list     List secret names without revealing their values
  beacon status          Inspect configuration without exposing secrets
  beacon run             Start the outbound collection worker
  beacon version         Print the build version
`)
}
