package collector

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

type githubRepository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
}

// Deliberately excludes the REST response's SSH public-key material.
type githubDeployKey struct {
	ID        int64           `json:"id"`
	Title     string          `json:"title"`
	ReadOnly  *bool           `json:"read_only"`
	CreatedAt string          `json:"created_at"`
	LastUsed  string          `json:"last_used"`
	Enabled   *bool           `json:"enabled"`
	AddedBy   json.RawMessage `json:"added_by"`
}

type githubPAT struct {
	TokenID             int64  `json:"token_id"`
	TokenName           string `json:"token_name"`
	TokenExpired        *bool  `json:"token_expired"`
	TokenExpiresAt      string `json:"token_expires_at"`
	TokenLastUsedAt     string `json:"token_last_used_at"`
	RepositorySelection string `json:"repository_selection"`
	Owner               struct {
		Login string `json:"login"`
	} `json:"owner"`
	Permissions map[string]map[string]string `json:"permissions"`
}

// GitHubKeys keeps the PAT and repository permission boundaries independent.
func GitHubKeys(ctx context.Context, credentials map[string]string) ([]protocol.KeyRecord, []protocol.KeyCoverage) {
	var pat []protocol.KeyRecord
	var patCoverage protocol.KeyCoverage
	done := make(chan struct{})
	go func() {
		defer close(done)
		pat, patCoverage = githubPATKeys(ctx, credentials)
	}()
	deploy, deployCoverage := githubDeployKeys(ctx, credentials)
	<-done
	return append(deploy, pat...), []protocol.KeyCoverage{deployCoverage, patCoverage}
}

func githubDeployKeyAddedBy(raw json.RawMessage) *string {
	var login string
	if json.Unmarshal(raw, &login) == nil {
		return stringPointer(login)
	}
	var user struct {
		Login string `json:"login"`
	}
	if json.Unmarshal(raw, &user) == nil {
		return stringPointer(user.Login)
	}
	return nil
}

// githubKeyPage never follows provider-supplied URLs or reports response bodies.
// Page numbers are generated locally; duplicate identities detect repeated pages.
func githubKeyPage[T any](ctx context.Context, token, endpoint string) ([]T, bool, bool) {
	response, err := githubRequest(ctx, token, endpoint)
	if err != nil {
		return nil, false, false
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return nil, false, false
	}
	var payload []T
	if decodeVendorJSON(response.Body, 16<<20, &payload) != nil || payload == nil || len(payload) > 100 {
		return nil, false, false
	}
	next := strings.Contains(response.Header.Get("Link"), `rel="next"`) || len(payload) == 100
	return payload, next, true
}

func githubDeployKeys(ctx context.Context, credentials map[string]string) ([]protocol.KeyRecord, protocol.KeyCoverage) {
	coverage := keyCoverageFailure("deploy_key", "GitHub repository deploy-key inventory was unavailable because the request was not configured, denied, unreachable, malformed, or exceeded a safety limit")
	if require(credentials, "token", "org") != nil {
		return nil, coverage
	}
	org := url.PathEscape(credentials["org"])
	repositories := make([]githubRepository, 0)
	seen := make(map[string]bool)
	complete := false
	for page := 1; page <= maxVendorPages; page++ {
		endpoint := "https://api.github.com/orgs/" + org + "/repos?type=all&per_page=100&page=" + strconv.Itoa(page)
		payload, next, ok := githubKeyPage[githubRepository](ctx, credentials["token"], endpoint)
		if !ok || len(repositories)+len(payload) > maxCollectedKeys {
			break
		}
		valid := true
		for _, repository := range payload {
			if repository.Name == "" || seen[repository.Name] {
				valid = false
				break
			}
			seen[repository.Name] = true
			repositories = append(repositories, repository)
		}
		if !valid {
			break
		}
		if !next {
			complete = true
			break
		}
	}
	coverage.ResourcesTotal = len(repositories)
	if len(repositories) == 0 {
		if complete {
			coverage.Status = "complete"
			coverage.Message = stringPointer("Only repositories visible to the configured credential are in scope")
		}
		return []protocol.KeyRecord{}, coverage
	}
	type scanResult struct {
		keys    []protocol.KeyRecord
		scanned bool
	}
	jobs := make(chan githubRepository)
	results := make(chan scanResult, 6)
	var wait sync.WaitGroup
	var keyCount atomic.Int64
	for range 6 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for repository := range jobs {
				fullName := repository.FullName
				if fullName == "" {
					fullName = credentials["org"] + "/" + repository.Name
				}
				found := make([]protocol.KeyRecord, 0)
				seenKeys := make(map[int64]bool)
				scanned := false
				for page := 1; page <= maxVendorPages; page++ {
					endpoint := "https://api.github.com/repos/" + org + "/" + url.PathEscape(repository.Name) + "/keys?per_page=100&page=" + strconv.Itoa(page)
					payload, next, ok := githubKeyPage[githubDeployKey](ctx, credentials["token"], endpoint)
					if !ok {
						break
					}
					valid := true
					for _, key := range payload {
						if key.ID <= 0 || key.ReadOnly == nil || seenKeys[key.ID] {
							valid = false
							break
						}
						seenKeys[key.ID] = true
						if keyCount.Add(1) > maxCollectedKeys {
							valid = false
							break
						}
						access := "write"
						if *key.ReadOnly {
							access = "read"
						}
						status := "unknown"
						if key.Enabled != nil {
							status = "disabled"
							if *key.Enabled {
								status = "active"
							}
						}
						found = append(found, protocol.KeyRecord{
							ID: strconv.FormatInt(key.ID, 10), Kind: "deploy_key", Name: key.Title,
							Resource: fullName, Access: access, Scopes: []string{}, Status: status,
							CreatedAt: normalizedRFC3339Pointer(key.CreatedAt), LastUsedAt: normalizedRFC3339Pointer(key.LastUsed),
							CreatedBy: githubDeployKeyAddedBy(key.AddedBy),
						})
					}
					if !valid {
						break
					}
					if !next {
						scanned = true
						break
					}
				}
				results <- scanResult{keys: found, scanned: scanned}
			}
		}()
	}
	go func() {
		for _, repository := range repositories {
			jobs <- repository
		}
		close(jobs)
		wait.Wait()
		close(results)
	}()
	collected := make([]protocol.KeyRecord, 0)
	for result := range results {
		collected = append(collected, result.keys...)
		if result.scanned {
			coverage.ResourcesScanned++
		}
	}
	coverage.Status = "partial"
	coverage.Message = stringPointer("Some repositories could not be fully inventoried; only visible repositories are in scope")
	if complete && coverage.ResourcesScanned == coverage.ResourcesTotal {
		coverage.Status = "complete"
		coverage.Message = stringPointer("Only visible repositories are in scope; GitHub does not report deploy-key owners or expiry")
	}
	sort.Slice(collected, func(i, j int) bool {
		if collected[i].Resource != collected[j].Resource {
			return collected[i].Resource < collected[j].Resource
		}
		return collected[i].ID < collected[j].ID
	})
	return collected, coverage
}

func githubPATKeys(ctx context.Context, credentials map[string]string) ([]protocol.KeyRecord, protocol.KeyCoverage) {
	coverage := keyCoverageFailure("api_key", "GitHub fine-grained PAT inventory was unavailable (configuration, permission, transport, response, or safety limit). This endpoint requires a GitHub App with organization Personal access tokens: read; personal access tokens cannot enumerate it")
	coverage.ResourcesTotal = 1
	if require(credentials, "token", "org") != nil {
		return nil, coverage
	}
	keys := make([]protocol.KeyRecord, 0)
	seen := make(map[int64]bool)
	complete := false
	for page := 1; page <= maxVendorPages; page++ {
		endpoint := "https://api.github.com/orgs/" + url.PathEscape(credentials["org"]) + "/personal-access-tokens?per_page=100&page=" + strconv.Itoa(page)
		payload, next, ok := githubKeyPage[githubPAT](ctx, credentials["token"], endpoint)
		if !ok || len(keys)+len(payload) > maxCollectedKeys {
			break
		}
		valid := true
		for _, token := range payload {
			if token.TokenID <= 0 || token.TokenExpired == nil || seen[token.TokenID] {
				valid = false
				break
			}
			seen[token.TokenID] = true
			scopes := make([]string, 0)
			for domain, permissions := range token.Permissions {
				for name, permission := range permissions {
					scopes = append(scopes, domain+":"+name+":"+permission)
				}
			}
			sort.Strings(scopes)
			status := "active"
			if *token.TokenExpired {
				status = "expired"
			}
			access := "unknown"
			if token.RepositorySelection != "" {
				access = "repositories: " + token.RepositorySelection
			}
			// access_granted_at is NOT token creation; creator is not owner.
			keys = append(keys, protocol.KeyRecord{
				ID: strconv.FormatInt(token.TokenID, 10), Kind: "api_key", Name: token.TokenName,
				Resource: credentials["org"], Access: access, Scopes: scopes, Status: status,
				LastUsedAt: normalizedRFC3339Pointer(token.TokenLastUsedAt), ExpiresAt: normalizedRFC3339Pointer(token.TokenExpiresAt),
				Owner: stringPointer(token.Owner.Login),
			})
		}
		if !valid {
			break
		}
		if !next {
			complete = true
			break
		}
	}
	if complete {
		coverage.Status = "complete"
		coverage.ResourcesScanned = 1
		coverage.Message = stringPointer("Approved organization fine-grained PATs only; classic PATs and pending requests are not enumerable here. Token creation time and creator are unavailable")
	} else if len(keys) > 0 {
		coverage.Status = "partial"
		coverage.Message = stringPointer("GitHub fine-grained PAT inventory was interrupted, denied, or exceeded safety limits; previously read metadata is retained")
	}
	return keys, coverage
}
