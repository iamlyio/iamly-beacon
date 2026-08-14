package collector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
