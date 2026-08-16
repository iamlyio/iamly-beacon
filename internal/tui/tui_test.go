package tui

import (
	"reflect"
	"testing"
)

func TestGuidedSecretProfiles(t *testing.T) {
	want := map[string][]string{
		"bamboohr": {"companyDomain", "apiKey"},
		"github":   {"org", "token"},
		"google":   {"clientEmail", "adminEmail", "privateKey"},
		"slack":    {"userToken"},
		"zoom":     {"accountId", "clientId", "clientSecret"},
	}
	if got := GuidedIntegrationNames(); !reflect.DeepEqual(got, []string{"bamboohr", "github", "google", "slack", "zoom"}) {
		t.Fatalf("guided integrations = %v", got)
	}
	for integration, fields := range want {
		if got := GuidedSecretFieldNames(integration); !reflect.DeepEqual(got, fields) {
			t.Errorf("%s fields = %v, want %v", integration, got, fields)
		}
	}
}

func TestUnknownGuidedSecretProfile(t *testing.T) {
	if fields := GuidedSecretFieldNames("unknown"); fields != nil {
		t.Fatalf("unknown fields = %v, want nil", fields)
	}
}
