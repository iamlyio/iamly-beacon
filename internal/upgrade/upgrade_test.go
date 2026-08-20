package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeDiscoversVerifiesAndReplacesBinary(t *testing.T) {
	directory := t.TempDir()
	current := filepath.Join(directory, "beacon")
	writeVersionScript(t, current, "v2.2.0-rc.4")
	archive := releaseArchive(t, "v2.2.0-rc.5")
	digest := sha256.Sum256(archive)

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/releases":
			if request.Header.Get("Accept") != "application/vnd.github+json" {
				t.Fatalf("Accept=%q", request.Header.Get("Accept"))
			}
			_, _ = response.Write([]byte(`[{"tag_name":"v9.0.0","draft":true},{"tag_name":"v2.2.0-rc.5","draft":false}]`))
		case "/download/v2.2.0-rc.5/SHA256SUMS":
			_, _ = fmt.Fprintf(response, "%s  iamly-beacon_linux_amd64.tar.gz\n", hex.EncodeToString(digest[:]))
		case "/download/v2.2.0-rc.5/iamly-beacon_linux_amd64.tar.gz":
			_, _ = response.Write(archive)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	client := testClient(server, current)
	var output bytes.Buffer
	if err := client.Run(context.Background(), "v2.2.0-rc.4", nil, &output); err != nil {
		t.Fatal(err)
	}
	if got := runVersion(t, current); got != "Beacon v2.2.0-rc.5" {
		t.Fatalf("installed version=%q", got)
	}
	if got := runVersion(t, current+".previous"); got != "Beacon v2.2.0-rc.4" {
		t.Fatalf("backup version=%q", got)
	}
	if !strings.Contains(output.String(), "Upgraded Beacon from v2.2.0-rc.4 to v2.2.0-rc.5") {
		t.Fatalf("output=%q", output.String())
	}
}

func TestUpgradeSupportsExplicitVersionAndCurrentVersionNoOp(t *testing.T) {
	directory := t.TempDir()
	current := filepath.Join(directory, "beacon")
	writeVersionScript(t, current, "v2.2.0-rc.5")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client := testClient(server, current)
	var output bytes.Buffer
	if err := client.Run(context.Background(), "v2.2.0-rc.5", []string{"--version", "v2.2.0-rc.5"}, &output); err != nil {
		t.Fatal(err)
	}
	if requests != 0 || !strings.Contains(output.String(), "already up to date") {
		t.Fatalf("requests=%d output=%q", requests, output.String())
	}
}

func TestUpgradeChecksumFailurePreservesCurrentBinary(t *testing.T) {
	directory := t.TempDir()
	current := filepath.Join(directory, "beacon")
	writeVersionScript(t, current, "v2.2.0-rc.4")
	archive := releaseArchive(t, "v2.2.0-rc.5")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch filepath.Base(request.URL.Path) {
		case "SHA256SUMS":
			_, _ = response.Write([]byte(strings.Repeat("0", 64) + "  iamly-beacon_linux_amd64.tar.gz\n"))
		default:
			_, _ = response.Write(archive)
		}
	}))
	defer server.Close()
	client := testClient(server, current)
	err := client.Run(context.Background(), "v2.2.0-rc.4", []string{"--version", "v2.2.0-rc.5"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "checksum verification failed") {
		t.Fatalf("error=%v", err)
	}
	if got := runVersion(t, current); got != "Beacon v2.2.0-rc.4" {
		t.Fatalf("current version=%q", got)
	}
	if _, statErr := os.Stat(current + ".previous"); !os.IsNotExist(statErr) {
		t.Fatalf("unexpected backup error=%v", statErr)
	}
}

func TestUpgradeRejectsDevelopmentAndUnsupportedPlatforms(t *testing.T) {
	client := DefaultClient()
	if err := client.Run(context.Background(), "dev", nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "development builds") {
		t.Fatalf("development error=%v", err)
	}
	client.GOOS = "windows"
	client.GOARCH = "amd64"
	client.Executable = func() (string, error) { return filepath.Join(t.TempDir(), "beacon.exe"), nil }
	client.ReleasesURL = "invalid://unused"
	err := client.Run(context.Background(), "v1.0.0", []string{"--version", "v1.0.1"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "Linux and macOS") {
		t.Fatalf("platform error=%v", err)
	}
}

func testClient(server *httptest.Server, executable string) Client {
	return Client{
		HTTPClient:     server.Client(),
		ReleasesURL:    server.URL + "/releases",
		ReleaseBaseURL: server.URL + "/download",
		Executable:     func() (string, error) { return executable, nil },
		GOOS:           "linux",
		GOARCH:         "amd64",
	}
}

func releaseArchive(t *testing.T, version string) []byte {
	t.Helper()
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	script := []byte("#!/bin/sh\n[ \"${1:-}\" = version ] && { echo 'Beacon " + version + "'; exit 0; }\nexit 1\n")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "beacon", Mode: 0o755, Size: int64(len(script)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(script); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func writeVersionScript(t *testing.T, path, version string) {
	t.Helper()
	content := "#!/bin/sh\n[ \"${1:-}\" = version ] && { echo 'Beacon " + version + "'; exit 0; }\nexit 1\n"
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func runVersion(t *testing.T, path string) string {
	t.Helper()
	result, err := exec.Command(path, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(result))
}
