package protocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	maxResponseBytes       = 1 << 20
	maxResultUploadBytes   = 32 << 20
	maxTestResultBytes     = 16 << 10
	resultUploadAttempts   = 3
	resultUploadRetryDelay = 250 * time.Millisecond
	maxControlPlaneError   = 64
)

var (
	jobIDPattern             = regexp.MustCompile(`^job_[A-Za-z0-9_-]{22}$`)
	testIDPattern            = regexp.MustCompile(`^tst_[A-Za-z0-9_-]{22}$`)
	leaseTokenPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	controlPlaneErrorPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	beaconIDPattern          = regexp.MustCompile(`^bcn_[A-Za-z0-9_-]{22}$`)
	supportedJobPlatforms    = map[string]struct{}{
		"anthropic":  {},
		"asana":      {},
		"bamboohr":   {},
		"canva":      {},
		"cloudflare": {},
		"dockerhub":  {},
		"figma":      {},
		"gcp":        {},
		"github":     {},
		"google":     {},
		"linear":     {},
		"notion":     {},
		"npmjs":      {},
		"openai":     {},
		"slack":      {},
		"tailscale":  {},
		"twingate":   {},
		"vercel":     {},
		"zoom":       {},
	}
)

type Client struct {
	BaseURL    string
	BeaconID   string
	PrivateKey ed25519.PrivateKey
	Version    string
	HTTPClient *http.Client
}

type Job struct {
	Kind             string   `json:"kind,omitempty"`
	ID               string   `json:"id"`
	ReviewRunID      int64    `json:"reviewRunId"`
	Platforms        []string `json:"platforms"`
	PendingPlatforms []string `json:"pendingPlatforms"`
	Platform         string   `json:"platform,omitempty"`
	LeaseToken       string   `json:"leaseToken"`
	ClaimGeneration  int64    `json:"claimGeneration"`
	LeaseExpiresAt   string   `json:"leaseExpiresAt,omitempty"`
}

type Member struct {
	ID          *string `json:"id"`
	Email       *string `json:"email"`
	Name        *string `json:"name"`
	Username    *string `json:"username"`
	Status      string  `json:"status"`
	Role        *string `json:"role"`
	CreatedAt   *string `json:"createdAt,omitempty"`
	LastLoginAt *string `json:"lastLoginAt"`
	Billable    *bool   `json:"billable,omitempty"`
}

type Spend struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// DeployKey is non-secret GitHub deploy-key inventory metadata. Beacon must
// never place private key material or a complete public key in this type.
type DeployKey struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Repository string  `json:"repository"`
	Access     string  `json:"access"`
	CreatedAt  *string `json:"createdAt,omitempty"`
	LastUsedAt *string `json:"lastUsedAt,omitempty"`
	AddedBy    *string `json:"addedBy,omitempty"`
}

type DeployKeyCoverage struct {
	Status           string  `json:"status"`
	ResourcesScanned int     `json:"resourcesScanned"`
	ResourcesTotal   int     `json:"resourcesTotal"`
	Message          *string `json:"message,omitempty"`
}

type Result struct {
	ProtocolVersion   int                `json:"protocolVersion"`
	Platform          string             `json:"platform"`
	CapturedAt        string             `json:"capturedAt"`
	Members           []Member           `json:"members"`
	Error             *string            `json:"error"`
	ObservedSpend     *Spend             `json:"observedSpend,omitempty"`
	DeployKeys        []DeployKey        `json:"deployKeys,omitempty"`
	DeployKeyCoverage *DeployKeyCoverage `json:"deployKeyCoverage,omitempty"`
}

func New(baseURL, beaconID, privateKeyText string) (Client, error) {
	privateKey, err := base64.RawURLEncoding.DecodeString(privateKeyText)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return Client{}, errors.New("Beacon signing private key is invalid")
	}
	parsed, err := url.ParseRequestURI(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return Client{}, errors.New("Beacon control-plane URL must be an origin")
	}
	localHTTP := parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")
	if parsed.Scheme != "https" && !localHTTP {
		return Client{}, errors.New("Beacon control-plane URL must use HTTPS")
	}
	if !beaconIDPattern.MatchString(beaconID) {
		return Client{}, errors.New("Beacon ID is invalid")
	}
	return Client{BaseURL: strings.TrimRight(baseURL, "/"), BeaconID: beaconID, PrivateKey: ed25519.PrivateKey(privateKey)}, nil
}

func (c Client) Poll(ctx context.Context, integrations []string) (*Job, error) {
	hostname, privateIPs := hostMetadata()
	body, _ := json.Marshal(map[string]any{
		"protocolVersion": 1,
		"integrations":    integrations,
		"capabilities":    []string{"integration_test_v1"},
		"hostname":        hostname,
		"privateIps":      privateIPs,
		"version":         c.Version,
	})
	response, status, err := c.request(ctx, "/api/v1/beacon/jobs/poll", body)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, responseError(status, response)
	}
	var payload struct {
		ProtocolVersion int `json:"protocolVersion"`
		Job             Job `json:"job"`
	}
	if json.Unmarshal(response, &payload) != nil || payload.ProtocolVersion != 1 ||
		!validJob(payload.Job) {
		return nil, errors.New("control plane returned an invalid job")
	}
	if payload.Job.Kind == "" {
		payload.Job.Kind = "review"
	}
	return &payload.Job, nil
}

func validJob(job Job) bool {
	if !leaseTokenPattern.MatchString(job.LeaseToken) || job.ClaimGeneration <= 0 {
		return false
	}
	if job.Kind == "integration_test" {
		if !testIDPattern.MatchString(job.ID) {
			return false
		}
		if _, supported := supportedJobPlatforms[job.Platform]; !supported {
			return false
		}
		if job.ReviewRunID != 0 || len(job.Platforms) != 0 || len(job.PendingPlatforms) != 0 {
			return false
		}
		leaseExpiresAt, err := time.Parse(time.RFC3339, job.LeaseExpiresAt)
		return err == nil && !leaseExpiresAt.IsZero()
	}
	if job.Kind != "" && job.Kind != "review" {
		return false
	}
	if !jobIDPattern.MatchString(job.ID) || job.ReviewRunID <= 0 || job.Platform != "" {
		return false
	}
	if job.LeaseExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, job.LeaseExpiresAt); err != nil {
			return false
		}
	}
	platforms, ok := validPlatformList(job.Platforms)
	if !ok {
		return false
	}
	pending, ok := validPlatformList(job.PendingPlatforms)
	if !ok || len(pending) > len(platforms) {
		return false
	}
	for platform := range pending {
		if _, requested := platforms[platform]; !requested {
			return false
		}
	}
	return true
}

var integrationTestErrorCodes = map[string]struct{}{
	"credentials_rejected":  {},
	"permission_denied":     {},
	"invalid_configuration": {},
	"rate_limited":          {},
	"vendor_unavailable":    {},
	"timed_out":             {},
	"unexpected_response":   {},
}

func (c Client) UploadIntegrationTest(ctx context.Context, job Job, ok bool, errorCode string) error {
	if job.Kind != "integration_test" || !validJob(job) {
		return errors.New("integration test job is invalid")
	}
	if ok && errorCode != "" {
		return errors.New("successful integration test cannot include an error code")
	}
	if !ok {
		if _, supported := integrationTestErrorCodes[errorCode]; !supported {
			return errors.New("failed integration test requires a supported error code")
		}
	}
	payload := struct {
		ProtocolVersion int    `json:"protocolVersion"`
		LeaseToken      string `json:"leaseToken"`
		ClaimGeneration int64  `json:"claimGeneration"`
		OK              bool   `json:"ok"`
		ErrorCode       string `json:"errorCode,omitempty"`
	}{
		ProtocolVersion: 1,
		LeaseToken:      job.LeaseToken,
		ClaimGeneration: job.ClaimGeneration,
		OK:              ok,
		ErrorCode:       errorCode,
	}
	body, err := json.Marshal(payload)
	if err != nil || len(body) > maxTestResultBytes {
		return errors.New("encode integration test result")
	}
	path := "/api/v1/beacon/integration-tests/" + url.PathEscape(job.ID) + "/results"
	for attempt := 0; attempt < resultUploadAttempts; attempt++ {
		response, status, requestErr := c.request(ctx, path, body)
		if requestErr == nil && status == http.StatusOK {
			return nil
		}
		retryable := requestErr != nil || status == http.StatusRequestTimeout ||
			status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500
		if !retryable || attempt == resultUploadAttempts-1 {
			if requestErr != nil {
				return requestErr
			}
			return responseError(status, response)
		}
		delay := resultUploadRetryDelay * time.Duration(1<<attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("integration test result retry exhausted")
}

func validPlatformList(platforms []string) (map[string]struct{}, bool) {
	if len(platforms) == 0 || len(platforms) > len(supportedJobPlatforms) {
		return nil, false
	}
	unique := make(map[string]struct{}, len(platforms))
	for _, platform := range platforms {
		if _, supported := supportedJobPlatforms[platform]; !supported {
			return nil, false
		}
		if _, duplicate := unique[platform]; duplicate {
			return nil, false
		}
		unique[platform] = struct{}{}
	}
	return unique, true
}

func (c Client) Heartbeat(ctx context.Context, job Job) error {
	body, _ := json.Marshal(map[string]any{
		"protocolVersion": 1,
		"leaseToken":      job.LeaseToken,
		"claimGeneration": job.ClaimGeneration,
	})
	response, status, err := c.request(ctx, "/api/v1/beacon/jobs/"+url.PathEscape(job.ID)+"/heartbeat", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return responseError(status, response)
	}
	return nil
}

func (c Client) Upload(ctx context.Context, job Job, result Result) error {
	result.ProtocolVersion = 1
	body, err := json.Marshal(struct {
		Result
		LeaseToken      string `json:"leaseToken"`
		ClaimGeneration int64  `json:"claimGeneration"`
	}{Result: result, LeaseToken: job.LeaseToken, ClaimGeneration: job.ClaimGeneration})
	if err != nil {
		return errors.New("encode collection result")
	}
	if len(body) > maxResultUploadBytes {
		return fmt.Errorf("collection result exceeds the %d MiB upload limit", maxResultUploadBytes>>20)
	}
	path := "/api/v1/beacon/jobs/" + url.PathEscape(job.ID) + "/results"
	for attempt := 0; attempt < resultUploadAttempts; attempt++ {
		response, status, requestErr := c.request(ctx, path, body)
		if requestErr == nil && status == http.StatusOK {
			return nil
		}
		retryable := requestErr != nil || status == http.StatusRequestTimeout ||
			status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500
		if !retryable || attempt == resultUploadAttempts-1 {
			if requestErr != nil {
				return requestErr
			}
			return responseError(status, response)
		}
		delay := resultUploadRetryDelay * time.Duration(1<<attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("control-plane upload retry exhausted")
}

func (c Client) request(ctx context.Context, path string, body []byte) ([]byte, int, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, 0, errors.New("generate request nonce")
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	hash := sha256.Sum256(body)
	message := strings.Join([]string{
		"iamly-beacon-request-v1", http.MethodPost, path, c.BeaconID, timestamp,
		nonce, base64.RawURLEncoding.EncodeToString(hash[:]),
	}, "\n")
	signature := ed25519.Sign(c.PrivateKey, []byte(message))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("create control-plane request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Iamly-Beacon", c.BeaconID)
	request.Header.Set("X-Iamly-Timestamp", timestamp)
	request.Header.Set("X-Iamly-Nonce", nonce)
	request.Header.Set("X-Iamly-Signature", base64.RawURLEncoding.EncodeToString(signature))
	client := &http.Client{Timeout: 30 * time.Second}
	if c.HTTPClient != nil {
		copy := *c.HTTPClient
		client = &copy
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("control-plane request failed: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, 0, errors.New("read control-plane response")
	}
	if len(responseBody) > maxResponseBytes {
		return nil, 0, errors.New("control-plane response is too large")
	}
	return responseBody, response.StatusCode, nil
}

func responseError(status int, body []byte) error {
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
		if len(payload.Error) <= maxControlPlaneError && controlPlaneErrorPattern.MatchString(payload.Error) {
			return fmt.Errorf("control plane rejected request: %s", payload.Error)
		}
	}
	return fmt.Errorf("control plane rejected request with HTTP %d", status)
}
