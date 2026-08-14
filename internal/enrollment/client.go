package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxResponseBytes = 64 << 10

type Identity struct {
	PrivateKey string
	PublicKey  string
}

type Result struct {
	BeaconID   string
	BeaconName string
}

type Client struct {
	HTTPClient *http.Client
}

type request struct {
	Token     string `json:"token"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
	Version   string `json:"version"`
}

type response struct {
	Beacon struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"beacon"`
	ProtocolVersion int    `json:"protocolVersion"`
	Error           string `json:"error"`
}

func GenerateIdentity() (Identity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("generate Beacon signing key: %w", err)
	}
	return Identity{
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
		PublicKey:  base64.RawURLEncoding.EncodeToString(publicKey),
	}, nil
}

func (c Client) Enroll(ctx context.Context, controlPlane, token, name, publicKey, version string) (Result, error) {
	body, err := json.Marshal(request{Token: token, Name: name, PublicKey: publicKey, Version: version})
	if err != nil {
		return Result{}, errors.New("encode enrollment request")
	}
	defer wipe(body)

	httpClient := http.Client{Timeout: 30 * time.Second}
	if c.HTTPClient != nil {
		httpClient = *c.HTTPClient
	}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 30 * time.Second
	}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	endpoint := strings.TrimRight(controlPlane, "/") + "/api/v1/beacon/enroll"
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		result, retry, err := enrollOnce(ctx, &httpClient, endpoint, body)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			break
		}
	}
	return Result{}, lastErr
}

// enrollOnce marks failures as retryable only when the request may have been
// committed but its successful response was lost. The control plane makes an
// exact token-and-public-key replay idempotent.
func enrollOnce(ctx context.Context, httpClient *http.Client, endpoint string, body []byte) (Result, bool, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, false, fmt.Errorf("create enrollment request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return Result{}, true, fmt.Errorf("enroll Beacon: %w", err)
	}
	defer httpResponse.Body.Close()

	limited := io.LimitReader(httpResponse.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return Result{}, true, fmt.Errorf("read enrollment response: %w", err)
	}
	if len(responseBody) > maxResponseBytes {
		return Result{}, false, errors.New("enrollment response is too large")
	}
	defer wipe(responseBody)
	var decoded response
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return Result{}, httpResponse.StatusCode >= 500 || httpResponse.StatusCode == http.StatusCreated,
			fmt.Errorf("enrollment failed with HTTP %d", httpResponse.StatusCode)
	}
	if httpResponse.StatusCode != http.StatusCreated {
		if knownEnrollmentError(decoded.Error) {
			return Result{}, httpResponse.StatusCode >= 500, fmt.Errorf("enrollment failed: %s", decoded.Error)
		}
		return Result{}, httpResponse.StatusCode >= 500, fmt.Errorf("enrollment failed with HTTP %d", httpResponse.StatusCode)
	}
	if decoded.ProtocolVersion != 1 || !validResponseText(decoded.Beacon.ID, 128) || !validResponseText(decoded.Beacon.Name, 80) {
		return Result{}, true, errors.New("control plane returned an invalid enrollment response")
	}
	return Result{BeaconID: decoded.Beacon.ID, BeaconName: decoded.Beacon.Name}, false, nil
}

func validResponseText(value string, maximumBytes int) bool {
	return value != "" && len(value) <= maximumBytes && strings.IndexFunc(value, func(character rune) bool {
		return character < 0x20 || character == 0x7f
	}) < 0
}

func knownEnrollmentError(value string) bool {
	switch value {
	case "enrollment_unavailable", "public_key_already_enrolled", "invalid_beacon_name",
		"invalid_beacon_version", "invalid_public_key", "request_too_large", "invalid_json",
		"enrollment_failed":
		return true
	default:
		return false
	}
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
