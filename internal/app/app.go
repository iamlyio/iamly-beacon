package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/reviam/beacon/internal/collector"
	"github.com/reviam/beacon/internal/config"
	"github.com/reviam/beacon/internal/enrollment"
	"github.com/reviam/beacon/internal/protocol"
	"github.com/reviam/beacon/internal/tui"
	"github.com/reviam/beacon/internal/vault"
)

var keyNamePattern = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
var integrationNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var credentialNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

const (
	maxCredentialImportBytes   = 1 << 20
	maxCredentialImportEntries = 256
	maxCredentialValueBytes    = 256 << 10
)

type App struct {
	version          string
	paths            config.Paths
	stdin            io.Reader
	stdout           io.Writer
	newKMS           func(context.Context) (kmsWrapper, error)
	enroller         beaconEnroller
	generateIdentity func() (enrollment.Identity, error)
}

type kmsWrapper interface {
	vault.KeyWrapper
	Close() error
}

type beaconEnroller interface {
	Enroll(context.Context, string, string, string, string, string) (enrollment.Result, error)
}

func New(version string) (*App, error) {
	paths, err := config.ResolvePaths()
	if err != nil {
		return nil, err
	}
	return &App{
		version: version,
		paths:   paths,
		stdin:   os.Stdin,
		stdout:  os.Stdout,
		newKMS: func(ctx context.Context) (kmsWrapper, error) {
			return vault.NewGCPKMS(ctx)
		},
		enroller:         enrollment.Client{},
		generateIdentity: enrollment.GenerateIdentity,
	}, nil
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
		return a.configure(ctx, arguments[1:])
	case "secret":
		if len(arguments) < 2 {
			return errors.New("use beacon secret set, beacon secret import --stdin, or beacon secret list")
		}
		switch arguments[1] {
		case "set":
			return a.storeSecret(ctx)
		case "import":
			return a.importSecrets(ctx, arguments[2:])
		case "list":
			return a.listSecrets(ctx)
		default:
			return errors.New("use beacon secret set, beacon secret import --stdin, or beacon secret list")
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
		return a.configure(ctx, nil)
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
	if !integrationNamePattern.MatchString(secret.Integration) || !credentialNamePattern.MatchString(secret.Name) {
		return errors.New("integration names must be lowercase; credential names may also use uppercase letters")
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
	fmt.Fprintf(a.output(), "✓ Stored %s.%s in the encrypted local vault\n", secret.Integration, secret.Name)
	return nil
}

type credentialImport struct {
	Version int                    `json:"version"`
	Secrets []credentialImportItem `json:"secrets"`
}

type credentialImportItem struct {
	Integration string `json:"integration"`
	Name        string `json:"name"`
	Value       string `json:"value"`
}

func (a *App) importSecrets(ctx context.Context, arguments []string) error {
	if len(arguments) != 1 || arguments[0] != "--stdin" {
		return errors.New("use beacon secret import --stdin; credential values are accepted only through stdin")
	}
	if file, ok := a.stdin.(*os.File); ok {
		info, err := file.Stat()
		if err != nil {
			return fmt.Errorf("inspect credential import stdin: %w", err)
		}
		if info.Mode()&os.ModeCharDevice != 0 {
			return errors.New("credential import stdin must be a pipe, not an interactive terminal")
		}
	}
	blob, err := io.ReadAll(io.LimitReader(a.stdin, maxCredentialImportBytes+1))
	if err != nil {
		return fmt.Errorf("read credential import from stdin: %w", err)
	}
	defer wipe(blob)
	if len(blob) > maxCredentialImportBytes {
		return errors.New("credential import exceeds the 1 MiB limit")
	}

	var payload credentialImport
	decoder := json.NewDecoder(bytes.NewReader(blob))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return errors.New("credential import JSON is invalid")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("credential import JSON must contain exactly one object")
	}
	defer wipeCredentialImport(&payload)
	if payload.Version != 1 {
		return errors.New("credential import version must be 1")
	}
	if len(payload.Secrets) == 0 {
		return errors.New("credential import must contain at least one secret")
	}
	if len(payload.Secrets) > maxCredentialImportEntries {
		return fmt.Errorf("credential import contains more than %d secrets", maxCredentialImportEntries)
	}
	seen := make(map[string]struct{}, len(payload.Secrets))
	integrations := make(map[string]struct{})
	for _, secret := range payload.Secrets {
		if !integrationNamePattern.MatchString(secret.Integration) {
			return errors.New("credential import contains an invalid integration name")
		}
		if !credentialNamePattern.MatchString(secret.Name) {
			return errors.New("credential import contains an invalid credential name")
		}
		if secret.Value == "" {
			return errors.New("credential import contains an empty credential value")
		}
		if len(secret.Value) > maxCredentialValueBytes {
			return errors.New("credential import contains a credential value larger than 256 KiB")
		}
		key := secret.Integration + "\x00" + secret.Name
		if _, duplicate := seen[key]; duplicate {
			return errors.New("credential import contains a duplicate integration and credential name")
		}
		seen[key] = struct{}{}
		integrations[secret.Integration] = struct{}{}
	}

	metadata, data, kms, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()
	if data.Integrations == nil {
		data.Integrations = make(map[string]map[string]string)
	}
	for _, secret := range payload.Secrets {
		if data.Integrations[secret.Integration] == nil {
			data.Integrations[secret.Integration] = make(map[string]string)
		}
		data.Integrations[secret.Integration][secret.Name] = secret.Value
	}
	if err := vault.NewStore(a.paths.Vault, metadata.KeyName, kms).Save(ctx, data); err != nil {
		return err
	}
	fmt.Fprintf(a.output(), "✓ Imported %d encrypted credentials across %d integrations\n", len(payload.Secrets), len(integrations))
	return nil
}

func wipeCredentialImport(payload *credentialImport) {
	for index := range payload.Secrets {
		payload.Secrets[index].Integration = ""
		payload.Secrets[index].Name = ""
		payload.Secrets[index].Value = ""
	}
	payload.Secrets = nil
}

func (a *App) listSecrets(ctx context.Context) error {
	_, data, kms, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()
	if len(data.Integrations) == 0 {
		fmt.Fprintln(a.output(), "No integration secrets configured.")
		return nil
	}
	integrations := make([]string, 0, len(data.Integrations))
	for integration := range data.Integrations {
		integrations = append(integrations, integration)
	}
	sort.Strings(integrations)
	for _, integration := range integrations {
		values := data.Integrations[integration]
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(a.output(), "%s.%s\n", integration, name)
		}
	}
	return nil
}

func (a *App) output() io.Writer {
	if a.stdout != nil {
		return a.stdout
	}
	return os.Stdout
}

func (a *App) openVault(ctx context.Context) (vault.Metadata, vault.Data, kmsWrapper, error) {
	metadata, err := vault.ReadMetadata(a.paths.Vault)
	if err != nil {
		return vault.Metadata{}, vault.Data{}, nil, err
	}
	kms, err := a.newKMS(ctx)
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

func (a *App) configure(ctx context.Context, arguments []string) error {
	initial := tui.SetupResult{Data: vault.Empty()}
	hasVault := false
	metadata, err := vault.ReadMetadata(a.paths.Vault)
	if err == nil {
		hasVault = true
		initial.KeyName = metadata.KeyName
		kms, openErr := a.newKMS(ctx)
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

	var result tui.SetupResult
	if len(arguments) == 0 {
		var saved bool
		result, saved, err = tui.Setup(initial)
		if err != nil || !saved {
			return err
		}
	} else {
		result, err = nonInteractiveSetup(arguments, initial, a.stdin)
		if err != nil {
			return err
		}
	}
	if err := validateSetup(result, initial, hasVault, a.version); err != nil {
		return err
	}

	kms, err := a.newKMS(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()
	if err := vault.SelfTest(ctx, result.KeyName, kms); err != nil {
		return err
	}

	didEnroll := result.EnrollmentToken != ""
	if didEnroll {
		identity, err := a.generateIdentity()
		if err != nil {
			return err
		}
		enrollmentToken := result.EnrollmentToken
		enrolled, err := a.enroller.Enroll(
			ctx,
			result.Data.ControlPlane.URL,
			enrollmentToken,
			result.Data.ControlPlane.BeaconName,
			identity.PublicKey,
			a.version,
		)
		result.EnrollmentToken = ""
		enrollmentToken = ""
		if err != nil {
			return err
		}
		result.Data.ControlPlane.BeaconID = enrolled.BeaconID
		result.Data.ControlPlane.BeaconName = enrolled.BeaconName
		result.Data.ControlPlane.SigningPrivateKey = identity.PrivateKey
		result.Data.ControlPlane.SigningPublicKey = identity.PublicKey
	} else {
		configuredURL := result.Data.ControlPlane.URL
		result.Data.ControlPlane = initial.Data.ControlPlane
		result.Data.ControlPlane.URL = configuredURL
	}
	if err := vault.NewStore(a.paths.Vault, result.KeyName, kms).Save(ctx, result.Data); err != nil {
		if didEnroll {
			return fmt.Errorf("enrollment succeeded but the local vault could not be saved; the enrollment token has been consumed: %w", err)
		}
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
	kms, err := a.newKMS(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()
	data, err := vault.NewStore(a.paths.Vault, metadata.KeyName, kms).Load(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Beacon status\n  Control plane: %s\n  Beacon name:   %s\n  Beacon ID:     %s\n  Vault:         encrypted · GCP KMS\n  Integrations:  %d configured\n", data.ControlPlane.URL, data.ControlPlane.BeaconName, data.ControlPlane.BeaconID, len(data.Integrations))
	return nil
}

func (a *App) run(ctx context.Context) error {
	_, data, kms, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()
	client, err := protocol.New(
		data.ControlPlane.URL,
		data.ControlPlane.BeaconID,
		data.ControlPlane.SigningPrivateKey,
	)
	if err != nil {
		return err
	}
	integrations := make([]string, 0, len(data.Integrations))
	for integration := range data.Integrations {
		if _, supported := collector.Supported[integration]; supported {
			integrations = append(integrations, integration)
		}
	}
	sort.Strings(integrations)
	if len(integrations) == 0 {
		return errors.New("no supported integration credentials are configured")
	}
	fmt.Fprintf(a.output(), "Beacon worker connected · %d integrations available\n", len(integrations))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		job, err := client.Poll(ctx, integrations)
		if err != nil {
			fmt.Fprintf(a.output(), "Beacon poll unavailable: %s\n", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				continue
			}
		}
		if job == nil {
			continue
		}
		if err := a.executeBeaconJob(ctx, client, *job, data.Integrations); err != nil {
			fmt.Fprintf(a.output(), "Review job %s finished with a transport error: %s\n", job.ID, err)
		}
	}
}

func (a *App) executeBeaconJob(ctx context.Context, client protocol.Client, job protocol.Job, credentials map[string]map[string]string) error {
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-jobCtx.Done():
				return
			case <-ticker.C:
				_ = client.Heartbeat(jobCtx, job)
			}
		}
	}()
	platforms := job.PendingPlatforms
	if len(platforms) == 0 {
		platforms = job.Platforms
	}
	fmt.Fprintf(a.output(), "Review job %s · collecting %d integrations\n", job.ID, len(platforms))
	var wait sync.WaitGroup
	errorsChannel := make(chan error, len(platforms))
	for _, platform := range platforms {
		platform := platform
		wait.Add(1)
		go func() {
			defer wait.Done()
			capturedAt := time.Now().UTC().Format(time.RFC3339Nano)
			result := protocol.Result{Platform: platform, CapturedAt: capturedAt, Members: []protocol.Member{}}
			collect, supported := collector.Supported[platform]
			localCredentials := credentials[platform]
			if !supported || localCredentials == nil {
				message := "integration is not configured in this Beacon"
				result.Error = &message
			} else {
				members, spend, err := collect(jobCtx, localCredentials)
				if err != nil {
					message := err.Error()
					result.Error = &message
				} else {
					result.Members = members
					result.ObservedSpend = spend
				}
			}
			if err := client.Upload(jobCtx, job, result); err != nil {
				errorsChannel <- fmt.Errorf("upload %s result: %w", platform, err)
				return
			}
			fmt.Fprintf(a.output(), "Review job %s · %s collection uploaded\n", job.ID, platform)
		}()
	}
	wait.Wait()
	cancel()
	<-heartbeatDone
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(a.output(), "Review job %s · collection complete\n", job.ID)
	return nil
}

func validateSetup(result, initial tui.SetupResult, hasVault bool, version string) error {
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
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("Reviam control-plane URL must not contain credentials, a query, or a fragment")
	}
	name := strings.TrimSpace(result.Data.ControlPlane.BeaconName)
	if name == "" || len(name) > 80 || strings.IndexFunc(name, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0 {
		return errors.New("Beacon name must contain 1 to 80 printable characters")
	}
	if !versionPattern.MatchString(version) {
		return errors.New("Beacon version is invalid")
	}
	if result.EnrollmentToken != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(result.EnrollmentToken)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != result.EnrollmentToken {
			return errors.New("enrollment token must be a canonical base64url-encoded 32-byte value")
		}
		return nil
	}
	if !hasVault || !completeIdentity(initial.Data.ControlPlane) {
		return errors.New("enrollment token is required until this Beacon has enrolled")
	}
	if name != initial.Data.ControlPlane.BeaconName {
		return errors.New("an enrollment token is required to change the Beacon name")
	}
	return nil
}

func completeIdentity(controlPlane vault.ControlPlane) bool {
	if controlPlane.BeaconID == "" || controlPlane.BeaconName == "" {
		return false
	}
	privateKey, err := base64.RawURLEncoding.DecodeString(controlPlane.SigningPrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize ||
		base64.RawURLEncoding.EncodeToString(privateKey) != controlPlane.SigningPrivateKey {
		return false
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(controlPlane.SigningPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(publicKey) != controlPlane.SigningPublicKey {
		return false
	}
	return string(ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)) == string(publicKey)
}

func nonInteractiveSetup(arguments []string, initial tui.SetupResult, stdin io.Reader) (tui.SetupResult, error) {
	flags := flag.NewFlagSet("beacon configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyName := flags.String("kms-key", "", "GCP KMS CryptoKey resource")
	controlPlane := flags.String("control-plane", "", "Reviam control-plane URL")
	name := flags.String("name", "", "Beacon name")
	tokenFromStdin := flags.Bool("enrollment-token-stdin", false, "read the enrollment token from stdin")
	if err := flags.Parse(arguments); err != nil {
		return tui.SetupResult{}, fmt.Errorf("invalid configure arguments: %w", err)
	}
	if flags.NArg() != 0 || *keyName == "" || *controlPlane == "" || *name == "" {
		return tui.SetupResult{}, errors.New("noninteractive configure requires --kms-key, --control-plane, and --name")
	}

	result := initial
	result.KeyName = strings.TrimSpace(*keyName)
	result.Data.ControlPlane.URL = strings.TrimRight(strings.TrimSpace(*controlPlane), "/")
	result.Data.ControlPlane.BeaconName = strings.TrimSpace(*name)
	if *tokenFromStdin {
		blob, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			return tui.SetupResult{}, fmt.Errorf("read enrollment token from stdin: %w", err)
		}
		defer wipe(blob)
		if len(blob) > 4096 {
			return tui.SetupResult{}, errors.New("enrollment token from stdin is too large")
		}
		result.EnrollmentToken = strings.TrimSpace(string(blob))
	}
	return result, nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func printHelp() {
	fmt.Print(`Beacon — Reviam's customer-hosted collector

Usage:
  beacon                 Open the terminal interface
  beacon configure       Configure and enroll interactively
  beacon configure --kms-key KEY --control-plane URL --name NAME [--enrollment-token-stdin]
                         Configure noninteractively; read a one-time token only from stdin
  beacon secret set      Enter and encrypt an integration secret
  beacon secret import --stdin
                         Import a versioned JSON credential bundle only from stdin
  beacon secret list     List secret names without revealing their values
  beacon status          Inspect configuration without exposing secrets
  beacon run             Start the outbound collection worker
  beacon version         Print the build version
`)
}
