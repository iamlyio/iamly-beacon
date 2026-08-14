package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

type Collector func(context.Context, map[string]string) ([]protocol.Member, *protocol.Spend, error)

var Supported = map[string]Collector{
	"google": Google,
	"github": GitHub,
	"slack":  Slack,
	"zoom":   Zoom,
}

var httpClient = &http.Client{Timeout: 40 * time.Second}

const vendorRequestAttempts = 3

func retryableVendorStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly ||
		status == http.StatusTooManyRequests || status >= 500
}

func vendorRetryDelay(response *http.Response, attempt int) time.Duration {
	delay := time.Duration(250*(1<<attempt)) * time.Millisecond
	if response != nil {
		if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds >= 0 {
			retryAfter := time.Duration(seconds) * time.Second
			if retryAfter > delay {
				delay = retryAfter
			}
		}
	}
	if delay > 5*time.Second {
		return 5 * time.Second
	}
	return delay
}

// doVendorRequest retries only transient transport, throttling, and upstream
// failures. Every attempt recreates the body and remains bounded by the
// collector context; credential and permission failures return immediately.
func doVendorRequest(ctx context.Context, request *http.Request) (*http.Response, error) {
	for attempt := 0; attempt < vendorRequestAttempts; attempt++ {
		next := request.Clone(ctx)
		if request.GetBody != nil {
			body, err := request.GetBody()
			if err != nil {
				return nil, err
			}
			next.Body = body
		}
		response, err := httpClient.Do(next)
		if err == nil && !retryableVendorStatus(response.StatusCode) {
			return response, nil
		}
		if attempt == vendorRequestAttempts-1 {
			return response, err
		}
		if response != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
		}
		timer := time.NewTimer(vendorRetryDelay(response, attempt))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, errors.New("vendor request retry exhausted")
}

func require(credentials map[string]string, names ...string) error {
	for _, name := range names {
		if credentials[name] == "" {
			return fmt.Errorf("missing local credential %s", name)
		}
	}
	return nil
}

func responseError(platform string, response *http.Response) error {
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s rejected the local credential (HTTP %d)", platform, response.StatusCode)
	}
	return fmt.Errorf("%s API returned HTTP %d", platform, response.StatusCode)
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	copy := value
	return &copy
}

func boolPointer(value bool) *bool { return &value }

func successful(status int) bool { return status >= 200 && status < 300 }

var errRepeatedCursor = errors.New("vendor returned a repeated pagination cursor")
