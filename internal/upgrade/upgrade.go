package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	defaultReleasesURL = "https://api.github.com/repos/iamlyio/iamly-beacon/releases?per_page=20"
	defaultReleaseBase = "https://github.com/iamlyio/iamly-beacon/releases/download"
	maxMetadataBytes   = 1 << 20
	maxArchiveBytes    = 128 << 20
	maxBinaryBytes     = 128 << 20
)

var releaseVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
var checksumPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Client struct {
	HTTPClient     *http.Client
	ReleasesURL    string
	ReleaseBaseURL string
	Executable     func() (string, error)
	GOOS           string
	GOARCH         string
}

func DefaultClient() Client {
	return Client{
		HTTPClient:     &http.Client{Timeout: 2 * time.Minute},
		ReleasesURL:    defaultReleasesURL,
		ReleaseBaseURL: defaultReleaseBase,
		Executable:     os.Executable,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
	}
}

func (client Client) Run(ctx context.Context, currentVersion string, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	targetVersion := flags.String("version", "", "release version to install")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("use beacon upgrade [--version vX.Y.Z]")
	}
	if !releaseVersionPattern.MatchString(currentVersion) {
		return errors.New("development builds cannot be upgraded automatically")
	}
	target := strings.TrimSpace(*targetVersion)
	if target == "" {
		var err error
		target, err = client.latestVersion(ctx)
		if err != nil {
			return err
		}
	}
	if !releaseVersionPattern.MatchString(target) {
		return errors.New("upgrade version must use the form vX.Y.Z")
	}
	if target == currentVersion {
		fmt.Fprintf(output, "Beacon is already up to date (%s).\n", currentVersion)
		return nil
	}
	return client.install(ctx, currentVersion, target, output)
}

func (client Client) latestVersion(ctx context.Context) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.ReleasesURL, nil)
	if err != nil {
		return "", errors.New("create release lookup request")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "iamly-beacon-upgrader")
	response, err := client.httpClient().Do(request)
	if err != nil {
		return "", errors.New("check for Beacon updates: release service could not be reached")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("check for Beacon updates: release service returned HTTP %d", response.StatusCode)
	}
	metadata, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes+1))
	if err != nil || len(metadata) > maxMetadataBytes {
		return "", errors.New("check for Beacon updates: release metadata is too large")
	}
	var releases []struct {
		TagName string `json:"tag_name"`
		Draft   bool   `json:"draft"`
	}
	if err := json.Unmarshal(metadata, &releases); err != nil {
		return "", errors.New("check for Beacon updates: invalid release metadata")
	}
	for _, release := range releases {
		if !release.Draft && releaseVersionPattern.MatchString(release.TagName) {
			return release.TagName, nil
		}
	}
	return "", errors.New("check for Beacon updates: no published release is available")
}

func (client Client) install(ctx context.Context, currentVersion, targetVersion string, output io.Writer) error {
	artifact, binaryName, err := client.artifactNames()
	if err != nil {
		return err
	}
	executablePath, err := client.Executable()
	if err != nil {
		return errors.New("locate the current Beacon binary")
	}
	executablePath, err = filepath.Abs(executablePath)
	if err != nil {
		return errors.New("resolve the current Beacon binary")
	}
	info, err := os.Lstat(executablePath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("the current Beacon binary is not a regular file")
	}
	directory := filepath.Dir(executablePath)
	temporaryDirectory, err := os.MkdirTemp(directory, ".beacon-upgrade-")
	if err != nil {
		return errors.New("the Beacon install directory is not writable")
	}
	defer os.RemoveAll(temporaryDirectory)

	checksums, err := client.download(ctx, client.releaseURL(targetVersion, "SHA256SUMS"), maxMetadataBytes)
	if err != nil {
		return err
	}
	expectedChecksum, err := expectedChecksum(checksums, artifact)
	if err != nil {
		return err
	}
	archive, err := client.download(ctx, client.releaseURL(targetVersion, artifact), maxArchiveBytes)
	if err != nil {
		return err
	}
	actualChecksum := sha256.Sum256(archive)
	if hex.EncodeToString(actualChecksum[:]) != expectedChecksum {
		return errors.New("upgrade archive checksum verification failed")
	}
	newBinary := filepath.Join(temporaryDirectory, binaryName)
	if err := extractBinary(archive, artifact, binaryName, newBinary); err != nil {
		return err
	}
	if err := os.Chmod(newBinary, info.Mode().Perm()); err != nil {
		return errors.New("prepare the upgraded Beacon binary")
	}
	if err := verifyBinary(ctx, newBinary, targetVersion); err != nil {
		return err
	}
	backupPath := executablePath + ".previous"
	if err := replaceBinary(executablePath, newBinary, backupPath); err != nil {
		return err
	}
	if err := verifyBinary(ctx, executablePath, targetVersion); err != nil {
		_ = os.Remove(executablePath)
		_ = os.Rename(backupPath, executablePath)
		return errors.New("the upgraded binary failed verification; the previous binary was restored")
	}
	if directoryHandle, openErr := os.Open(directory); openErr == nil {
		_ = directoryHandle.Sync()
		_ = directoryHandle.Close()
	}
	fmt.Fprintf(output, "Upgraded Beacon from %s to %s.\nPrevious binary: %s\nRestart any running Beacon service to use the new version.\n", currentVersion, targetVersion, backupPath)
	return nil
}

func (client Client) httpClient() *http.Client {
	if client.HTTPClient != nil {
		return client.HTTPClient
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

func (client Client) artifactNames() (string, string, error) {
	if client.GOOS != "linux" && client.GOOS != "darwin" {
		return "", "", errors.New("automatic upgrades currently support Linux and macOS; use install.sh on another platform")
	}
	if client.GOARCH != "amd64" && client.GOARCH != "arm64" {
		return "", "", errors.New("automatic upgrades require an AMD64 or ARM64 Beacon build")
	}
	return fmt.Sprintf("iamly-beacon_%s_%s.tar.gz", client.GOOS, client.GOARCH), "beacon", nil
}

func (client Client) releaseURL(version, filename string) string {
	return strings.TrimRight(client.ReleaseBaseURL, "/") + "/" + url.PathEscape(version) + "/" + filename
}

func (client Client) download(ctx context.Context, address string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("create upgrade download request")
	}
	request.Header.Set("User-Agent", "iamly-beacon-upgrader")
	response, err := client.httpClient().Do(request)
	if err != nil {
		return nil, errors.New("download Beacon upgrade: release service could not be reached")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download Beacon upgrade: release service returned HTTP %d", response.StatusCode)
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, errors.New("download Beacon upgrade")
	}
	if int64(len(value)) > limit {
		return nil, errors.New("download Beacon upgrade: release artifact is too large")
	}
	return value, nil
}

func expectedChecksum(checksums []byte, artifact string) (string, error) {
	match := ""
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != artifact {
			continue
		}
		if match != "" || !checksumPattern.MatchString(fields[0]) {
			return "", errors.New("release checksums do not contain exactly one valid upgrade entry")
		}
		match = fields[0]
	}
	if match == "" {
		return "", errors.New("release checksums do not contain exactly one valid upgrade entry")
	}
	return match, nil
}

func extractBinary(archive []byte, artifact, binaryName, destination string) error {
	if !strings.HasSuffix(artifact, ".tar.gz") {
		return errors.New("unsupported Beacon release archive")
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return errors.New("open Beacon release archive")
	}
	defer gzipReader.Close()
	tape := tar.NewReader(gzipReader)
	for {
		header, nextErr := tape.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return errors.New("read Beacon release archive")
		}
		if header.Name != binaryName {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > maxBinaryBytes {
			return errors.New("release archive contains an invalid Beacon binary")
		}
		file, createErr := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
		if createErr != nil {
			return errors.New("prepare the upgraded Beacon binary")
		}
		_, copyErr := io.CopyN(file, tape, header.Size)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return errors.New("extract the upgraded Beacon binary")
		}
		return nil
	}
	return errors.New("release archive does not contain the Beacon binary")
}

func verifyBinary(ctx context.Context, path, version string) error {
	command := exec.CommandContext(ctx, path, "version")
	result, err := command.Output()
	if err != nil || strings.TrimSpace(string(result)) != "Beacon "+version {
		return errors.New("release binary reported an unexpected version")
	}
	return nil
}

func replaceBinary(currentPath, newPath, backupPath string) error {
	oldBackup := backupPath + ".old"
	_ = os.Remove(oldBackup)
	hadBackup := false
	if _, err := os.Lstat(backupPath); err == nil {
		if err := os.Rename(backupPath, oldBackup); err != nil {
			return errors.New("preserve the previous Beacon backup")
		}
		hadBackup = true
	} else if !os.IsNotExist(err) {
		return errors.New("inspect the previous Beacon backup")
	}
	restoreOldBackup := func() {
		if hadBackup {
			_ = os.Rename(oldBackup, backupPath)
		}
	}
	if err := os.Rename(currentPath, backupPath); err != nil {
		restoreOldBackup()
		return errors.New("replace Beacon: move the current binary; check install-directory permissions")
	}
	if err := os.Rename(newPath, currentPath); err != nil {
		_ = os.Rename(backupPath, currentPath)
		restoreOldBackup()
		return errors.New("replace Beacon: install the new binary; the previous binary was restored")
	}
	_ = os.Remove(oldBackup)
	return nil
}
