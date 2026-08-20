package tui

import (
	"reflect"
	"testing"
)

func TestGuidedSecretProfiles(t *testing.T) {
	want := map[string][]string{
		"anthropic":  {"adminApiKey"},
		"asana":      {"token", "workspaceGid"},
		"bamboohr":   {"companyDomain", "apiKey"},
		"canva":      {"token"},
		"cloudflare": {"accountId", "token"},
		"dockerhub":  {"identifier", "secret", "org"},
		"figma":      {"token", "tenantId"},
		"gcp":        {"clientEmail", "resourceScope", "privateKey"},
		"github":     {"org", "token"},
		"google":     {"clientEmail", "adminEmail", "privateKey"},
		"linear":     {"apiKey"},
		"notion":     {"token"},
		"npmjs":      {"token", "org"},
		"openai":     {"adminApiKey"},
		"slack":      {"userToken"},
		"tailscale":  {"clientId", "clientSecret"},
		"twingate":   {"network", "apiToken"},
		"vercel":     {"token", "teamId"},
		"zoom":       {"accountId", "clientId", "clientSecret"},
	}
	if got := GuidedIntegrationNames(); !reflect.DeepEqual(got, []string{"anthropic", "asana", "bamboohr", "canva", "cloudflare", "dockerhub", "figma", "gcp", "github", "google", "linear", "notion", "npmjs", "openai", "slack", "tailscale", "twingate", "vercel", "zoom"}) {
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
