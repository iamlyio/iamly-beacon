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
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iamlyio/iamly-beacon/internal/collector"
	"github.com/iamlyio/iamly-beacon/internal/config"
	"github.com/iamlyio/iamly-beacon/internal/enrollment"
	"github.com/iamlyio/iamly-beacon/internal/protocol"
	"github.com/iamlyio/iamly-beacon/internal/tui"
	"github.com/iamlyio/iamly-beacon/internal/upgrade"
	"github.com/iamlyio/iamly-beacon/internal/vault"
)

var googleKeyNamePattern = regexp.MustCompile(`^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
var integrationNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var credentialNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
var beaconIDPattern = regexp.MustCompile(`^bcn_[A-Za-z0-9_-]{22}$`)

const (
	betaControlPlane           = "https://beacon-beta.iamly.io"
	maxCredentialImportBytes   = 1 << 20
	maxCredentialImportEntries = 256
	maxCredentialValueBytes    = 256 << 10
	collectorTimeout           = 10 * time.Minute
)

type App struct {
	version           string
	paths             config.Paths
	stdin             io.Reader
	stdout            io.Writer
	newKeyWrapper     func(context.Context, vault.Provider, string, bool) (kmsWrapper, error)
	enroller          beaconEnroller
	generateIdentity  func() (enrollment.Identity, error)
	collectionTimeout time.Duration
	upgrade           func(context.Context, string, []string, io.Writer) error
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
	upgradeClient := upgrade.DefaultClient()
	return &App{
		version: version,
		paths:   paths,
		stdin:   os.Stdin,
		stdout:  os.Stdout,
		newKeyWrapper: func(ctx context.Context, provider vault.Provider, keyName string, create bool) (kmsWrapper, error) {
			switch provider {
			case vault.ProviderLocal:
				if create {
					return vault.OpenOrCreateLocalKey(paths.LocalKey)
				}
				return vault.OpenLocalKey(paths.LocalKey)
			case vault.ProviderGoogleKMS:
				return vault.NewGCPKMS(ctx)
			case vault.ProviderAWSKMS:
				return vault.NewAWSKMS(ctx, keyName)
			default:
				return nil, fmt.Errorf("unsupported vault key provider %q", provider)
			}
		},
		enroller:          enrollment.Client{},
		generateIdentity:  enrollment.GenerateIdentity,
		collectionTimeout: collectorTimeout,
		upgrade:           upgradeClient.Run,
	}, nil
}

func (a *App) keyWrapper(ctx context.Context, provider vault.Provider, keyName string, create bool) (kmsWrapper, error) {
	if a.newKeyWrapper != nil {
		return a.newKeyWrapper(ctx, provider, keyName, create)
	}
	return nil, fmt.Errorf("vault key provider %q is not configured", provider)
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
			return a.storeSecret(ctx, arguments[2:])
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
	case "upgrade":
		return a.upgrade(ctx, a.version, arguments[1:], a.stdout)
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
		return a.storeSecret(ctx, nil)
	case tui.Status:
		return a.status(ctx)
	case tui.Run:
		return a.run(ctx)
	default:
		return nil
	}
}

func (a *App) storeSecret(ctx context.Context, arguments []string) error {
	if len(arguments) > 1 {
		return errors.New("use beacon secret set [integration]")
	}
	metadata, data, kms, err := a.openVault(ctx)
	if err != nil {
		return err
	}
	defer kms.Close()

	integration := ""
	values := map[string]string{}
	if len(arguments) == 1 {
		guided, saved, promptErr := tui.GuidedSecrets(arguments[0])
		if promptErr != nil || !saved {
			return promptErr
		}
		integration = guided.Integration
		values = guided.Values
	} else {
		secret, saved, promptErr := tui.Secret()
		if promptErr != nil || !saved {
			return promptErr
		}
		integration = secret.Integration
		values[secret.Name] = secret.Value
	}
	if !integrationNamePattern.MatchString(integration) {
		return errors.New("integration names must be lowercase")
	}
	for name, value := range values {
		if !credentialNamePattern.MatchString(name) {
			return errors.New("credential names must begin with a letter and contain only letters, numbers, underscores, or hyphens")
		}
		if value == "" {
			return fmt.Errorf("%s.%s is required", integration, name)
		}
		if len(value) > maxCredentialValueBytes {
			return fmt.Errorf("%s.%s exceeds the 256 KiB credential limit", integration, name)
		}
	}
	if integration == "bamboohr" {
		if validationErr := collector.ValidateBambooHRCredentials(values); validationErr != nil {
			return validationErr
		}
	}
	if data.Integrations == nil {
		data.Integrations = make(map[string]map[string]string)
	}
	if data.Integrations[integration] == nil {
		data.Integrations[integration] = make(map[string]string)
	}
	for name, value := range values {
		data.Integrations[integration][name] = value
	}
	if err := vault.NewStore(a.paths.Vault, metadata.Provider, metadata.KeyName, kms).Save(ctx, data); err != nil {
		return err
	}
	if len(arguments) == 1 {
		fmt.Fprintf(a.output(), "✓ Configured %s with %d encrypted values in the local vault\n", integration, len(values))
	} else {
		for name := range values {
			fmt.Fprintf(a.output(), "✓ Stored %s.%s in the encrypted local vault\n", integration, name)
		}
	}
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
	if err := vault.NewStore(a.paths.Vault, metadata.Provider, metadata.KeyName, kms).Save(ctx, data); err != nil {
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
	kms, err := a.keyWrapper(ctx, metadata.Provider, metadata.KeyName, false)
	if err != nil {
		return vault.Metadata{}, vault.Data{}, nil, err
	}
	data, err := vault.NewStore(a.paths.Vault, metadata.Provider, metadata.KeyName, kms).Load(ctx)
	if err != nil {
		kms.Close()
		return vault.Metadata{}, vault.Data{}, nil, err
	}
	return metadata, data, kms, nil
}

func (a *App) configure(ctx context.Context, arguments []string) error {
	options, err := parseConfigureOptions(arguments)
	if err != nil {
		return err
	}
	initial := tui.SetupResult{Data: vault.Empty()}
	hasVault := false
	metadata, err := vault.ReadMetadata(a.paths.Vault)
	if err == nil {
		hasVault = true
		initial.Provider = metadata.Provider
		initial.KeyName = metadata.KeyName
		kms, openErr := a.keyWrapper(ctx, metadata.Provider, metadata.KeyName, false)
		if openErr != nil {
			return openErr
		}
		defer kms.Close()
		initial.Data, err = vault.NewStore(a.paths.Vault, metadata.Provider, metadata.KeyName, kms).Load(ctx)
		if err != nil {
			return err
		}
	} else if !errors.Is(err, vault.ErrNotFound) {
		return err
	}
	provider := initial.Provider
	if options.providerExplicit {
		provider = options.provider
	} else if provider == "" {
		provider = vault.ProviderLocal
	}
	initial.Provider = provider
	if hasVault && provider != metadata.Provider {
		initial.KeyName = ""
	}
	if provider == vault.ProviderLocal {
		initial.KeyName = vault.LocalKeyName
	}
	initial.Data.ControlPlane.URL = betaControlPlane

	var result tui.SetupResult
	if !options.nonInteractive {
		var saved bool
		result, saved, err = tui.Setup(initial)
		if err != nil || !saved {
			return err
		}
	} else {
		result, err = nonInteractiveSetup(options, initial, a.stdin)
		if err != nil {
			return err
		}
	}
	if err := validateSetup(result, initial, hasVault, a.version); err != nil {
		return err
	}

	kms, err := a.keyWrapper(ctx, result.Provider, result.KeyName, result.Provider == vault.ProviderLocal)
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
		if !beaconIDPattern.MatchString(enrolled.BeaconID) || invalidDisplayText(enrolled.BeaconName, 80) {
			return errors.New("control plane returned an invalid Beacon identity")
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
	if err := vault.NewStore(a.paths.Vault, result.Provider, result.KeyName, kms).Save(ctx, result.Data); err != nil {
		if didEnroll {
			return fmt.Errorf("enrollment succeeded but the local vault could not be saved; the enrollment token has been consumed: %w", err)
		}
		return err
	}
	fmt.Printf("✓ Beacon configuration encrypted with %s at %s\n", providerLabel(result.Provider), a.paths.Vault)
	return nil
}

func (a *App) status(ctx context.Context) error {
	metadata, err := vault.ReadMetadata(a.paths.Vault)
	if err != nil {
		return err
	}
	kms, err := a.keyWrapper(ctx, metadata.Provider, metadata.KeyName, false)
	if err != nil {
		return err
	}
	defer kms.Close()
	data, err := vault.NewStore(a.paths.Vault, metadata.Provider, metadata.KeyName, kms).Load(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Beacon status\n  Control plane: %s\n  Beacon name:   %s\n  Beacon ID:     %s\n  Vault:         encrypted · %s\n  Integrations:  %d configured\n", data.ControlPlane.URL, data.ControlPlane.BeaconName, data.ControlPlane.BeaconID, providerLabel(metadata.Provider), len(data.Integrations))
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
	client.Version = a.version
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
	errorsChannel := make(chan error, len(job.PendingPlatforms)+1)
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		consecutiveFailures := 0
		for {
			select {
			case <-jobCtx.Done():
				return
			case <-ticker.C:
				if err := client.Heartbeat(jobCtx, job); err != nil {
					consecutiveFailures++
					if consecutiveFailures >= 3 {
						errorsChannel <- fmt.Errorf("heartbeat lease: %w", err)
						cancel()
						return
					}
					continue
				}
				consecutiveFailures = 0
			}
		}
	}()
	platforms := job.PendingPlatforms
	if len(platforms) == 0 {
		platforms = job.Platforms
	}
	fmt.Fprintf(a.output(), "Review job %s · collecting %d integrations\n", job.ID, len(platforms))
	var wait sync.WaitGroup
	var outputMutex sync.Mutex
	for _, platform := range platforms {
		platform := platform
		wait.Add(1)
		go func() {
			defer wait.Done()
			timeout := a.collectionTimeout
			if timeout <= 0 {
				timeout = collectorTimeout
			}
			collectionCtx, stopCollection := context.WithTimeout(jobCtx, timeout)
			defer stopCollection()
			result := protocol.Result{Platform: platform, Members: []protocol.Member{}}
			collect, supported := collector.Supported[platform]
			localCredentials := credentials[platform]
			if !supported || localCredentials == nil {
				message := "integration is not configured in this Beacon"
				result.Error = &message
			} else {
				// A collector returns only after its app-specific profile, activity,
				// role, and billing enrichment is complete. Upload that normalized
				// app snapshot immediately; never wait for sibling connectors.
				members, spend, err := collect(collectionCtx, localCredentials)
				if err != nil {
					message := err.Error()
					if errors.Is(collectionCtx.Err(), context.DeadlineExceeded) {
						message = "collection exceeded the 10 minute deadline"
					}
					result.Error = &message
				} else {
					result.Members = members
					result.ObservedSpend = spend
					if platform == "github" {
						deployKeys, coverage := collector.GitHubDeployKeys(collectionCtx, localCredentials)
						result.DeployKeys = deployKeys
						result.DeployKeyCoverage = &coverage
					}
				}
			}
			result.CapturedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if err := client.Upload(jobCtx, job, result); err != nil {
				errorsChannel <- fmt.Errorf("upload %s result: %w", platform, err)
				return
			}
			outputMutex.Lock()
			fmt.Fprintf(a.output(), "Review job %s · %s collection uploaded\n", job.ID, platform)
			outputMutex.Unlock()
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
	switch result.Provider {
	case vault.ProviderLocal:
		if result.KeyName != vault.LocalKeyName {
			return errors.New("local vault storage uses Beacon's managed local key")
		}
	case vault.ProviderGoogleKMS:
		if !googleKeyNamePattern.MatchString(result.KeyName) {
			return errors.New("Google KMS key must use projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}")
		}
	case vault.ProviderAWSKMS:
		if invalidAWSKeyName(result.KeyName) {
			return errors.New("AWS KMS key must be a key ARN, key ID, alias ARN, or alias/name")
		}
	default:
		return errors.New("choose local, Google KMS, or AWS KMS vault storage")
	}
	if result.Data.ControlPlane.URL != betaControlPlane {
		return errors.New("Beacon control plane must be the IAMly beta service")
	}
	name := strings.TrimSpace(result.Data.ControlPlane.BeaconName)
	if invalidDisplayText(name, 80) {
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

func invalidAWSKeyName(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || len(value) > 2048 || strings.IndexFunc(value, func(character rune) bool {
		return character <= 0x20 || character == 0x7f
	}) >= 0
}

func providerLabel(provider vault.Provider) string {
	switch provider {
	case vault.ProviderLocal:
		return "local key"
	case vault.ProviderGoogleKMS:
		return "Google Cloud KMS"
	case vault.ProviderAWSKMS:
		return "AWS KMS"
	default:
		return string(provider)
	}
}

func completeIdentity(controlPlane vault.ControlPlane) bool {
	if !beaconIDPattern.MatchString(controlPlane.BeaconID) || invalidDisplayText(controlPlane.BeaconName, 80) {
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

func invalidDisplayText(value string, maximumBytes int) bool {
	return strings.TrimSpace(value) == "" || len(value) > maximumBytes || strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) >= 0
}

type configureOptions struct {
	provider         vault.Provider
	providerExplicit bool
	nonInteractive   bool
	keyName          string
	name             string
	tokenFromStdin   bool
}

func parseConfigureOptions(arguments []string) (configureOptions, error) {
	flags := flag.NewFlagSet("beacon configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	local := flags.Bool("local", false, "protect the vault with a local key file")
	googleKMS := flags.Bool("google-kms", false, "protect the vault with Google Cloud KMS")
	awsKMS := flags.Bool("aws-kms", false, "protect the vault with AWS KMS")
	keyName := flags.String("kms-key", "", "Google Cloud or AWS KMS key identifier")
	name := flags.String("name", "", "Beacon name")
	tokenFromStdin := flags.Bool("enrollment-token-stdin", false, "read the enrollment token from stdin")
	if err := flags.Parse(arguments); err != nil {
		return configureOptions{}, fmt.Errorf("invalid configure arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return configureOptions{}, errors.New("configure accepts flags only")
	}
	selected := 0
	options := configureOptions{
		keyName:        strings.TrimSpace(*keyName),
		name:           strings.TrimSpace(*name),
		tokenFromStdin: *tokenFromStdin,
	}
	if *local {
		selected++
		options.provider = vault.ProviderLocal
	}
	if *googleKMS {
		selected++
		options.provider = vault.ProviderGoogleKMS
	}
	if *awsKMS {
		selected++
		options.provider = vault.ProviderAWSKMS
	}
	if selected > 1 {
		return configureOptions{}, errors.New("choose only one of --local, --google-kms, or --aws-kms")
	}
	options.providerExplicit = selected == 1
	if options.keyName != "" && !options.providerExplicit {
		// Preserve the original --kms-key invocation as Google KMS.
		options.provider = vault.ProviderGoogleKMS
		options.providerExplicit = true
	}
	options.nonInteractive = options.keyName != "" || options.name != "" || options.tokenFromStdin
	return options, nil
}

func nonInteractiveSetup(options configureOptions, initial tui.SetupResult, stdin io.Reader) (tui.SetupResult, error) {
	if options.name == "" {
		return tui.SetupResult{}, errors.New("noninteractive configure requires --name")
	}
	if initial.Provider != vault.ProviderLocal && options.keyName == "" && initial.KeyName == "" {
		return tui.SetupResult{}, errors.New("noninteractive cloud KMS configure requires --kms-key")
	}
	if initial.Provider == vault.ProviderLocal && options.keyName != "" {
		return tui.SetupResult{}, errors.New("--local does not accept --kms-key")
	}

	result := initial
	if options.keyName != "" {
		result.KeyName = options.keyName
	}
	result.Data.ControlPlane.BeaconName = options.name
	if options.tokenFromStdin {
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
	fmt.Print(`Beacon — IAMly customer-hosted collector

Usage:
  beacon                 Open the terminal interface
  beacon configure [--local | --google-kms | --aws-kms]
                         Configure interactively against the IAMly beta control plane
  beacon configure [STORAGE] --name NAME [--kms-key KEY] [--enrollment-token-stdin]
                         Configure noninteractively; cloud KMS backends require --kms-key
  beacon secret set [integration]
                         Configure one supported integration through guided prompts
  beacon secret import --stdin
                         Import a versioned JSON credential bundle only from stdin
  beacon secret list     List secret names without revealing their values
  beacon status          Inspect configuration without exposing secrets
  beacon run             Start the outbound collection worker
  beacon upgrade [--version vX.Y.Z]
                         Install the latest or selected verified Beacon release
  beacon version         Print the build version
`)
}
