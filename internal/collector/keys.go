package collector

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const maxCollectedKeys = 100_000

// CollectKeys is independent of account collection: provider permission failures
// are coverage observations, never a reason to discard successful member data.
func CollectKeys(ctx context.Context, platform string, credentials map[string]string) ([]protocol.KeyRecord, []protocol.KeyCoverage) {
	var keys []protocol.KeyRecord
	var coverage []protocol.KeyCoverage
	switch platform {
	case "github":
		keys, coverage = GitHubKeys(ctx, credentials)
	case "linear":
		keys, coverage = LinearKeys(ctx, credentials)
	case "gcp":
		keys, coverage = GCPKeys(ctx, credentials)
	case "aws":
		keys, coverage = AWSKeys(ctx, credentials)
	default:
		return nil, nil
	}
	return sanitizeKeyInventory(keys, coverage, credentials)
}

// Only credential-bearing fields are secret. Resource selectors such as an
// organization name, region, or service-account email are inventory metadata.
func keyCredentialSecrets(credentials map[string]string) []string {
	var secrets []string
	for name, value := range credentials {
		lower := strings.ToLower(name)
		if value != "" && (strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "key")) {
			secrets = append(secrets, value)
		}
	}
	return secrets
}

func sanitizeKeyInventory(keys []protocol.KeyRecord, coverage []protocol.KeyCoverage, credentials map[string]string) ([]protocol.KeyRecord, []protocol.KeyCoverage) {
	secrets := keyCredentialSecrets(credentials)
	unsafe := func(value string, maximum int) bool {
		if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum {
			return true
		}
		for _, secret := range secrets {
			if strings.Contains(value, secret) {
				return true
			}
		}
		return false
	}
	seen := make(map[string]bool)
	filtered := keys[:0]
	incomplete := make(map[string]bool)
	for _, key := range keys {
		invalid := strings.TrimSpace(key.ID) == "" || strings.TrimSpace(key.Resource) == "" || unsafe(key.ID, 1000) || unsafe(key.Resource, 1000) || unsafe(key.Name, 500) || unsafe(key.Access, 500) || len(key.Scopes) > 100
		for _, value := range []*string{key.Owner, key.CreatedBy} {
			if value != nil && unsafe(*value, 500) {
				invalid = true
			}
		}
		for _, scope := range key.Scopes {
			if unsafe(scope, 500) {
				invalid = true
			}
		}
		if invalid || len(filtered) == maxCollectedKeys {
			incomplete[key.Kind] = true
			continue
		}
		identity := key.Kind + "\x00" + key.Resource + "\x00" + key.ID
		if seen[identity] {
			incomplete[key.Kind] = true
			continue
		}
		seen[identity] = true
		if key.Scopes == nil {
			key.Scopes = []string{}
		}
		for _, timestamp := range []**string{&key.CreatedAt, &key.LastUsedAt, &key.ExpiresAt} {
			if *timestamp != nil {
				*timestamp = normalizedRFC3339Pointer(**timestamp)
			}
		}
		filtered = append(filtered, key)
	}
	for index := range coverage {
		item := &coverage[index]
		if item.Message != nil && unsafe(*item.Message, 500) {
			item.Message = stringPointer("Provider key inventory details were withheld")
		}
		if incomplete[item.Kind] {
			item.Status = "partial"
			item.Message = stringPointer("Some key metadata was withheld because it exceeded safety bounds, was duplicated, or contained a local credential")
		}
	}
	return filtered, coverage
}

func keyCoverageFailure(kind, message string) protocol.KeyCoverage {
	return protocol.KeyCoverage{Kind: kind, Status: "unavailable", Message: stringPointer(message)}
}
