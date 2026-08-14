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
	"strings"
	"time"
)

const (
	maxResponseBytes       = 1 << 20
	resultUploadAttempts   = 3
	resultUploadRetryDelay = 250 * time.Millisecond
)

type Client struct {
	BaseURL    string
	BeaconID   string
	PrivateKey ed25519.PrivateKey
	Version    string
	HTTPClient *http.Client
}

type Job struct {
	ID               string   `json:"id"`
	ReviewRunID      int64    `json:"reviewRunId"`
	Platforms        []string `json:"platforms"`
	PendingPlatforms []string `json:"pendingPlatforms"`
	LeaseToken       string   `json:"leaseToken"`
	ClaimGeneration  int64    `json:"claimGeneration"`
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
	return Client{BaseURL: strings.TrimRight(baseURL, "/"), BeaconID: beaconID, PrivateKey: ed25519.PrivateKey(privateKey)}, nil
}

func (c Client) Poll(ctx context.Context, integrations []string) (*Job, error) {
	hostname, privateIPs := hostMetadata()
	body, _ := json.Marshal(map[string]any{
		"protocolVersion": 1,
		"integrations":    integrations,
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
		payload.Job.ID == "" ||
		((payload.Job.LeaseToken == "") != (payload.Job.ClaimGeneration == 0)) {
		return nil, errors.New("control plane returned an invalid job")
	}
	if len(payload.Job.PendingPlatforms) == 0 {
		payload.Job.PendingPlatforms = payload.Job.Platforms
	}
	return &payload.Job, nil
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
		"reviam-beacon-request-v1", http.MethodPost, path, c.BeaconID, timestamp,
		nonce, base64.RawURLEncoding.EncodeToString(hash[:]),
	}, "\n")
	signature := ed25519.Sign(c.PrivateKey, []byte(message))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, errors.New("create control-plane request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Reviam-Beacon", c.BeaconID)
	request.Header.Set("X-Reviam-Timestamp", timestamp)
	request.Header.Set("X-Reviam-Nonce", nonce)
	request.Header.Set("X-Reviam-Signature", base64.RawURLEncoding.EncodeToString(signature))
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
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
		return fmt.Errorf("control plane rejected request: %s", payload.Error)
	}
	return fmt.Errorf("control plane rejected request with HTTP %d", status)
}
