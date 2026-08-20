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
	available := make(map[string]bool, len(guided))
	for _, integration := range guided {
		available[integration] = true
	}
	for integration := range collector.Supported {
		if !available[integration] {
			t.Errorf("supported collector %q has no guided secret profile", integration)
		}
		if _, available := collector.ConnectionTesters[integration]; !available {
			t.Errorf("supported collector %q has no connection tester", integration)
		}
	}
}
