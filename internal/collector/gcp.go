package collector

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

// Cloud Asset Inventory's searchAllIamPolicies method accepts the
// cloud-platform OAuth scope. Effective access remains read-only because the
// dedicated service account is granted only Cloud Asset Viewer and Service
// Usage Consumer in the reviewed scope.
const gcpOAuthScope = "https://www.googleapis.com/auth/cloud-platform"

var gcpResourceScopePattern = regexp.MustCompile(`^(?:organizations/[0-9]+|folders/[0-9]+|projects/(?:[0-9]+|[a-z][a-z0-9-]{4,28}[a-z0-9]))$`)

func gcpAccessToken(ctx context.Context, credentials map[string]string) (string, error) {
	if err := require(credentials, "clientEmail", "resourceScope", "privateKey"); err != nil {
		return "", err
	}
	if !gcpResourceScopePattern.MatchString(credentials["resourceScope"]) {
		return "", errors.New("GCP resourceScope must be an organization, folder, or project resource name")
	}
	block, _ := pem.Decode([]byte(normalizeGooglePrivateKey(credentials["privateKey"])))
	if block == nil {
		return "", errors.New("GCP private key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New("GCP private key is not valid PKCS#8")
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("GCP private key is not RSA")
	}

	now := time.Now().Unix()
	encode := func(value any) string {
		blob, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(blob)
	}
	unsigned := encode(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + encode(map[string]any{
		"iss": credentials["clientEmail"], "scope": gcpOAuthScope,
		"aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600,
	})
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("sign GCP authorization assertion")
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)},
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return "", errors.New("GCP token exchange could not be reached")
	}
	defer response.Body.Close()
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	decodeErr := decodeVendorJSON(response.Body, 1<<20, &payload)
	if !successful(response.StatusCode) {
		return "", responseError("GCP", response)
	}
	if decodeErr != nil || payload.AccessToken == "" {
		return "", errors.New("GCP token exchange returned invalid JSON")
	}
	return payload.AccessToken, nil
}

type gcpPrincipal struct {
	kind  string
	email string
	ID    string
	roles map[string]struct{}
}

func parseGCPPrincipal(member string) (gcpPrincipal, bool) {
	statusPrefix := ""
	value := member
	if strings.HasPrefix(value, "deleted:") {
		statusPrefix = "deleted:"
		value = strings.TrimPrefix(value, "deleted:")
	}
	kind, email, ok := strings.Cut(value, ":")
	if !ok || (kind != "user" && kind != "serviceAccount") || email == "" {
		return gcpPrincipal{}, false
	}
	cleanEmail := strings.SplitN(email, "?uid=", 2)[0]
	if cleanEmail == "" {
		return gcpPrincipal{}, false
	}
	return gcpPrincipal{kind: kind, email: cleanEmail, ID: statusPrefix + value, roles: map[string]struct{}{}}, true
}

// GCP inventories direct user and service-account principals in IAM allow
// policies under one explicitly configured Cloud Asset Inventory scope.
func GCP(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	token, err := gcpAccessToken(ctx, credentials)
	if err != nil {
		return nil, nil, err
	}
	principals := map[string]gcpPrincipal{}
	cursor := ""
	seen := map[string]bool{}
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse("https://cloudasset.googleapis.com/v1/" + credentials["resourceScope"] + ":searchAllIamPolicies")
		query := endpoint.Query()
		query.Set("pageSize", "500")
		query.Set("query", "memberTypes:(user OR serviceAccount)")
		if cursor != "" {
			query.Set("pageToken", cursor)
		}
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("GCP IAM policy collection could not be reached")
		}
		var payload struct {
			Results []struct {
				Policy struct {
					Bindings []struct {
						Role    string   `json:"role"`
						Members []string `json:"members"`
					} `json:"bindings"`
				} `json:"policy"`
			} `json:"results"`
			Next string `json:"nextPageToken"`
		}
		decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("GCP", response)
		}
		if decodeErr != nil {
			return nil, nil, errors.New("GCP IAM policy collection returned invalid JSON")
		}
		for _, result := range payload.Results {
			for _, binding := range result.Policy.Bindings {
				for _, rawMember := range binding.Members {
					principal, ok := parseGCPPrincipal(rawMember)
					if !ok {
						continue
					}
					current, exists := principals[principal.ID]
					if !exists {
						if len(principals) >= maxCollectedMembers {
							return nil, nil, errMemberLimit
						}
						current = principal
					}
					if binding.Role != "" {
						current.roles[binding.Role] = struct{}{}
					}
					principals[principal.ID] = current
				}
			}
		}
		if payload.Next == "" {
			return normalizeGCPPrincipals(principals), nil, nil
		}
		if seen[payload.Next] {
			return nil, nil, errRepeatedCursor
		}
		seen[payload.Next] = true
		cursor = payload.Next
	}
	return nil, nil, errPaginationLimit
}

func normalizeGCPPrincipals(principals map[string]gcpPrincipal) []protocol.Member {
	keys := make([]string, 0, len(principals))
	for key := range principals {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	members := make([]protocol.Member, 0, len(keys))
	for _, key := range keys {
		principal := principals[key]
		roles := make([]string, 0, len(principal.roles))
		for role := range principal.roles {
			roles = append(roles, role)
		}
		sort.Strings(roles)
		status := "active"
		if strings.HasPrefix(principal.ID, "deleted:") {
			status = "deactivated"
		}
		role := strings.Join(roles, ", ")
		roleCount := len(roles)
		if principal.kind == "serviceAccount" {
			if role == "" {
				role = "service account"
			} else {
				role = "service account · " + role
			}
		}
		if len(role) > 500 {
			role = fmt.Sprintf("%d direct IAM roles", roleCount)
			if principal.kind == "serviceAccount" {
				role = "service account · " + role
			}
		}
		members = append(members, protocol.Member{
			ID: stringPointer(principal.ID), Email: stringPointer(principal.email),
			Name: stringPointer(principal.email), Status: status, Role: stringPointer(role),
		})
	}
	return members
}
