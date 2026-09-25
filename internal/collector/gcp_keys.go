package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var gcpKeyRingNamePattern = regexp.MustCompile(`^projects/[a-zA-Z0-9-]+/locations/[a-z0-9-]+/keyRings/[a-zA-Z0-9_-]+$`)
var gcpKeyNamePartPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)
var gcpVersionIDPattern = regexp.MustCompile(`^[0-9]+$`)
var gcpMetadataEnumPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,99}$`)
var gcpDurationPattern = regexp.MustCompile(`^[0-9]{1,12}(\.[0-9]{1,9})?s$`)

type gcpKeyVersionMetadata struct {
	Name            string `json:"name"`
	State           string `json:"state"`
	CreateTime      string `json:"createTime"`
	DestroyTime     string `json:"destroyTime"`
	Algorithm       string `json:"algorithm"`
	ProtectionLevel string `json:"protectionLevel"`
}

type gcpCryptoKeyMetadata struct {
	Name             string                `json:"name"`
	Purpose          string                `json:"purpose"`
	CreateTime       string                `json:"createTime"`
	RotationPeriod   string                `json:"rotationPeriod"`
	NextRotationTime string                `json:"nextRotationTime"`
	Primary          gcpKeyVersionMetadata `json:"primary"`
}

type gcpKeyRingAsset struct {
	Name         string   `json:"name"`
	Project      string   `json:"project"`
	Folders      []string `json:"folders"`
	Organization string   `json:"organization"`
}

// Cloud Asset Inventory authoritatively bounds discovery to resourceScope;
// parent names and ancestry are checked before following any KMS resource.
func gcpKeyRingInScope(asset gcpKeyRingAsset, scope string) (string, bool) {
	const prefix = "//cloudkms.googleapis.com/"
	if !strings.HasPrefix(asset.Name, prefix) {
		return "", false
	}
	name := strings.TrimPrefix(asset.Name, prefix)
	if len(name) > 1000 || !gcpKeyRingNamePattern.MatchString(name) {
		return "", false
	}
	switch {
	case strings.HasPrefix(scope, "organizations/"):
		return name, asset.Organization == scope
	case strings.HasPrefix(scope, "folders/"):
		for _, folder := range asset.Folders {
			if folder == scope {
				return name, true
			}
		}
		return "", false
	default:
		return name, strings.HasPrefix(name, scope+"/") || asset.Project == scope
	}
}

func gcpCloudKeyPage(ctx context.Context, inventory *cloudKeyInventory, token, endpoint string, query url.Values, output any) error {
	if err := inventory.request(); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+query.Encode(), nil)
	if err != nil {
		return errors.New("invalid GCP key metadata request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return errors.New("GCP key metadata request failed")
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return responseError("GCP", response)
	}
	return decodeVendorJSON(response.Body, 8<<20, output)
}

func gcpKeyMetadataScopes(key gcpCryptoKeyMetadata) []string {
	scopes := []string{"metadata:logical_key", "state:not_exposed"}
	if gcpDurationPattern.MatchString(key.RotationPeriod) {
		scopes = append(scopes, "rotation-period:"+key.RotationPeriod)
	}
	if next := normalizedRFC3339Pointer(key.NextRotationTime); next != nil {
		scopes = append(scopes, "next-rotation:"+*next)
	}
	if gcpMetadataEnumPattern.MatchString(key.Primary.State) {
		scopes = append(scopes, "primary-state:"+key.Primary.State)
	}
	return scopes
}

func gcpKeyVersionStatus(state string) string {
	switch state {
	case "ENABLED":
		return "active"
	case "DISABLED":
		return "disabled"
	case "DESTROY_SCHEDULED":
		return "pending_deletion"
	case "DESTROYED":
		return "revoked"
	default:
		return "unknown"
	}
}

func gcpKeyPurpose(purpose string) string {
	if gcpMetadataEnumPattern.MatchString(purpose) {
		return purpose
	}
	return "unknown"
}

func gcpCollectKeyVersions(ctx context.Context, inventory *cloudKeyInventory, token string, key gcpCryptoKeyMetadata) error {
	query := url.Values{"pageSize": {"1000"}, "view": {"BASIC"}, "fields": {"cryptoKeyVersions(name,state,createTime,destroyTime,algorithm,protectionLevel),nextPageToken"}}
	seen := map[string]bool{}
	for range maxVendorPages {
		var payload struct {
			Versions []gcpKeyVersionMetadata `json:"cryptoKeyVersions"`
			Next     string                  `json:"nextPageToken"`
		}
		if err := gcpCloudKeyPage(ctx, inventory, token, "https://cloudkms.googleapis.com/v1/"+key.Name+"/cryptoKeyVersions", query, &payload); err != nil {
			return err
		}
		for _, version := range payload.Versions {
			prefix := key.Name + "/cryptoKeyVersions/"
			id := strings.TrimPrefix(version.Name, prefix)
			if !strings.HasPrefix(version.Name, prefix) || len(version.Name) > 1000 || !gcpVersionIDPattern.MatchString(id) {
				inventory.partial = true
				continue
			}
			scopes := []string{"metadata:key_version"}
			if gcpMetadataEnumPattern.MatchString(version.Algorithm) {
				scopes = append(scopes, "algorithm:"+version.Algorithm)
			}
			if gcpMetadataEnumPattern.MatchString(version.ProtectionLevel) {
				scopes = append(scopes, "protection:"+version.ProtectionLevel)
			}
			if when := normalizedRFC3339Pointer(version.DestroyTime); when != nil {
				scopes = append(scopes, "scheduled-destruction:"+*when)
			}
			if key.Primary.Name == version.Name {
				scopes = append(scopes, "primary:true")
			}
			if err := inventory.add(protocol.KeyRecord{
				ID: version.Name, Kind: "encryption_key", Name: key.Name[strings.LastIndex(key.Name, "/")+1:] + " / version " + id,
				Resource: key.Name, Access: gcpKeyPurpose(key.Purpose), Scopes: scopes,
				Status: gcpKeyVersionStatus(version.State), CreatedAt: normalizedRFC3339Pointer(version.CreateTime),
			}); err != nil {
				return err
			}
		}
		if payload.Next == "" {
			return nil
		}
		if len(payload.Next) > 4096 || seen[payload.Next] {
			return errRepeatedCursor
		}
		seen[payload.Next] = true
		query.Set("pageToken", payload.Next)
	}
	return errPaginationLimit
}

func gcpCollectKeyRing(ctx context.Context, inventory *cloudKeyInventory, token, ring string) error {
	query := url.Values{"pageSize": {"1000"}, "versionView": {"BASIC"}, "fields": {"cryptoKeys(name,purpose,createTime,rotationPeriod,nextRotationTime,primary(name,state)),nextPageToken"}}
	seenPages := map[string]bool{}
	seenKeys := map[string]bool{}
	complete := true
	for range maxVendorPages {
		var payload struct {
			Keys []gcpCryptoKeyMetadata `json:"cryptoKeys"`
			Next string                 `json:"nextPageToken"`
		}
		if err := gcpCloudKeyPage(ctx, inventory, token, "https://cloudkms.googleapis.com/v1/"+ring+"/cryptoKeys", query, &payload); err != nil {
			return err
		}
		for _, key := range payload.Keys {
			prefix := ring + "/cryptoKeys/"
			name := strings.TrimPrefix(key.Name, prefix)
			if !strings.HasPrefix(key.Name, prefix) || len(key.Name) > 1000 || !gcpKeyNamePartPattern.MatchString(name) {
				inventory.partial = true
				complete = false
				continue
			}
			if seenKeys[key.Name] {
				continue
			}
			seenKeys[key.Name] = true
			if err := inventory.add(protocol.KeyRecord{ID: key.Name, Kind: "encryption_key", Name: name, Resource: ring,
				Access: gcpKeyPurpose(key.Purpose), Scopes: gcpKeyMetadataScopes(key), Status: "unknown", CreatedAt: normalizedRFC3339Pointer(key.CreateTime),
			}); err != nil {
				return err
			}
			if err := gcpCollectKeyVersions(ctx, inventory, token, key); err != nil {
				inventory.partial = true
				complete = false
				if ctx.Err() != nil || errors.Is(err, errCloudKeyLimit) {
					return err
				}
			}
		}
		if payload.Next == "" {
			if complete {
				inventory.scanned++
			}
			return nil
		}
		if len(payload.Next) > 4096 || seenPages[payload.Next] {
			return errRepeatedCursor
		}
		seenPages[payload.Next] = true
		query.Set("pageToken", payload.Next)
	}
	return errPaginationLimit
}

// GCPKeys reads only metadata. Logical keys and individual versions are separate
// records; a logical key has no native state, so it is not assigned its primary
// version's state. No decrypt/export/public-key, IAM policy, or audit-log API runs.
func GCPKeys(ctx context.Context, credentials map[string]string) ([]protocol.KeyRecord, []protocol.KeyCoverage) {
	inventory := &cloudKeyInventory{}
	scope := credentials["resourceScope"]
	if !gcpResourceScopePattern.MatchString(scope) {
		scope = "invalid resourceScope"
	}
	details := "Key-ring discovery uses Cloud Asset Inventory in the configured scope (subject to indexing delay), across all locations. Counts are key rings; records include logical keys and versions. Last use, owner, and creator are not exposed by KMS metadata and remain unknown; audit logs are not queried."
	finish := func() ([]protocol.KeyRecord, []protocol.KeyCoverage) { return inventory.result("GCP "+scope, details) }
	token, err := gcpAccessToken(ctx, credentials)
	if err != nil {
		inventory.partial = true
		return finish()
	}
	query := url.Values{"pageSize": {"500"}, "assetTypes": {"cloudkms.googleapis.com/KeyRing"}, "readMask": {"name,project,folders,organization"}}
	seenPages := map[string]bool{}
	seenRings := map[string]bool{}
	for range maxVendorPages {
		var payload struct {
			Results []gcpKeyRingAsset `json:"results"`
			Next    string            `json:"nextPageToken"`
		}
		if err := gcpCloudKeyPage(ctx, inventory, token, "https://cloudasset.googleapis.com/v1/"+scope+":searchAllResources", query, &payload); err != nil {
			inventory.partial = true
			return finish()
		}
		inventory.discovered = true
		for _, asset := range payload.Results {
			ring, valid := gcpKeyRingInScope(asset, scope)
			if !valid {
				inventory.partial = true
				continue
			}
			if seenRings[ring] {
				continue
			}
			if len(seenRings) >= maxCloudKeys {
				inventory.partial = true
				return finish()
			}
			seenRings[ring] = true
			inventory.total++
			if err := gcpCollectKeyRing(ctx, inventory, token, ring); err != nil {
				inventory.partial = true
				if ctx.Err() != nil || errors.Is(err, errCloudKeyLimit) {
					return finish()
				}
			}
		}
		if payload.Next == "" {
			return finish()
		}
		if len(payload.Next) > 4096 || seenPages[payload.Next] {
			inventory.partial = true
			return finish()
		}
		seenPages[payload.Next] = true
		query.Set("pageToken", payload.Next)
	}
	inventory.partial = true
	return finish()
}
