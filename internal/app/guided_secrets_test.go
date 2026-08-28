package app

import (
	"testing"

	"github.com/iamlyio/iamly-beacon/internal/collector"
	"github.com/iamlyio/iamly-beacon/internal/protocol"
	"github.com/iamlyio/iamly-beacon/internal/tui"
)

func TestIntegrationRegistriesMatchSupportedCollectors(t *testing.T) {
	guided := tui.GuidedIntegrationNames()
	protocolNames := protocol.SupportedJobPlatformNames()
	if len(guided) != len(collector.Supported) {
		t.Fatalf("guided integrations = %v, supported collectors = %d", guided, len(collector.Supported))
	}
	if len(protocolNames) != len(collector.Supported) {
		t.Fatalf("protocol integrations = %v, supported collectors = %d", protocolNames, len(collector.Supported))
	}
	availableGuided := make(map[string]bool, len(guided))
	for _, integration := range guided {
		availableGuided[integration] = true
	}
	availableProtocol := make(map[string]bool, len(protocolNames))
	for _, integration := range protocolNames {
		availableProtocol[integration] = true
	}
	for integration := range collector.Supported {
		if !availableGuided[integration] {
			t.Errorf("supported collector %q has no guided secret profile", integration)
		}
		if _, available := collector.ConnectionTesters[integration]; !available {
			t.Errorf("supported collector %q has no connection tester", integration)
		}
		if !availableProtocol[integration] {
			t.Errorf("supported collector %q is not accepted by the job protocol", integration)
		}
	}
}
