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
		spec := guidedSecretSpecs[integration]
		got := make([]string, len(spec.fields))
		for index, field := range spec.fields {
			got[index] = field.name
		}
		if !reflect.DeepEqual(got, fields) {
			t.Errorf("%s fields = %v, want %v", integration, got, fields)
		}
	}
}
