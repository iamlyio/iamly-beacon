package app

import (
	"testing"

	"github.com/iamlyio/iamly-beacon/internal/collector"
	"github.com/iamlyio/iamly-beacon/internal/tui"
)

func TestEveryCollectorHasGuidedSecretSetup(t *testing.T) {
	guided := tui.GuidedIntegrationNames()
	if len(guided) != len(collector.Supported) {
		t.Fatalf("guided integrations = %v, supported collectors = %d", guided, len(collector.Supported))
	}
	for integration := range collector.Supported {
		if fields := tui.GuidedSecretFieldNames(integration); len(fields) == 0 {
			t.Errorf("supported collector %q has no guided secret profile", integration)
		}
	}
}
