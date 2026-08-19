package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

func githubRequest(ctx context.Context, token, endpoint string) (*http.Response, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return doVendorRequest(ctx, request)
}

type githubRepository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
}

type githubDeployKey struct {
	ID        int64           `json:"id"`
	Title     string          `json:"title"`
	ReadOnly  bool            `json:"read_only"`
	CreatedAt string          `json:"created_at"`
	LastUsed  string          `json:"last_used"`
	Enabled   *bool           `json:"enabled"`
	AddedBy   json.RawMessage `json:"added_by"`
}

type githubBillingSummary struct {
	UsageItems []struct {
		NetAmount float64 `json:"netAmount"`
	} `json:"usageItems"`
}

// githubTokenOwnerEmail uses GitHub's Email addresses: Read permission only
// for the authenticated token owner. GitHub does not allow this endpoint to
// reveal private addresses belonging to other organization members.
func githubTokenOwnerEmail(ctx context.Context, token string) (string, string, bool) {
	profileResponse, err := githubRequest(ctx, token, "https://api.github.com/user")
	if err != nil {
		return "", "", false
	}
	var profile struct {
		Login string `json:"login"`
	}
	profileErr := decodeVendorJSON(profileResponse.Body, 1<<20, &profile)
	profileStatus := profileResponse.StatusCode
	profileResponse.Body.Close()
	if !successful(profileStatus) || profileErr != nil || profile.Login == "" {
		return "", "", false
	}

	emailResponse, err := githubRequest(ctx, token, "https://api.github.com/user/emails?per_page=100")
	if err != nil {
		return "", "", false
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	emailErr := decodeVendorJSON(emailResponse.Body, 1<<20, &emails)
	emailStatus := emailResponse.StatusCode
	emailResponse.Body.Close()
	if !successful(emailStatus) || emailErr != nil {
		return "", "", false
	}
	for _, email := range emails {
		if email.Primary && email.Verified && email.Email != "" {
			return profile.Login, email.Email, true
		}
	}
	for _, email := range emails {
		if email.Verified && email.Email != "" {
			return profile.Login, email.Email, true
		}
	}
	return "", "", false
}

// githubBillingSpend returns GitHub's current-month net billed usage. Billing
// enrichment is deliberately best effort: a preview endpoint or billing-plan
// limitation must not discard a valid account snapshot.
func githubBillingSpend(ctx context.Context, token, org string) *protocol.Spend {
	endpoint := "https://api.github.com/organizations/" + url.PathEscape(org) + "/settings/billing/usage/summary"
	response, err := githubRequest(ctx, token, endpoint)
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return nil
	}
	var payload githubBillingSummary
	if decodeVendorJSON(response.Body, 16<<20, &payload) != nil {
		return nil
	}
	total := 0.0
	for _, item := range payload.UsageItems {
		if math.IsNaN(item.NetAmount) || math.IsInf(item.NetAmount, 0) {
			return nil
		}
		total += item.NetAmount
	}
	// Credits can make an individual usage item negative. The normalized
	// spend contract is non-negative, so report the net payable floor.
	total = math.Max(0, math.Round(total*10000)/10000)
	return &protocol.Spend{Amount: total, Currency: "USD"}
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

// GitHubDeployKeys inventories repository deploy keys without returning key
// material. A denied repository produces partial coverage, not a connector
// failure, so account collection and accessible repositories remain useful.
func GitHubDeployKeys(ctx context.Context, credentials map[string]string) ([]protocol.DeployKey, protocol.DeployKeyCoverage) {
	coverage := protocol.DeployKeyCoverage{Status: "unavailable"}
	if err := require(credentials, "token", "org"); err != nil {
		message := err.Error()
		coverage.Message = &message
		return nil, coverage
	}
	org := url.PathEscape(credentials["org"])
	repositories := make([]githubRepository, 0)
	for page := 1; page <= maxVendorPages; page++ {
		endpoint := "https://api.github.com/orgs/" + org + "/repos?type=all&per_page=100&page=" + strconv.Itoa(page)
		response, err := githubRequest(ctx, credentials["token"], endpoint)
		if err != nil {
			message := "GitHub repository inventory could not be reached"
			coverage.Message = &message
			return nil, coverage
		}
		var payload []githubRepository
		decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
		status := response.StatusCode
		response.Body.Close()
		if !successful(status) {
			message := "GitHub did not permit repository inventory"
			coverage.Message = &message
			return nil, coverage
		}
		if decodeErr != nil {
			message := "GitHub returned invalid repository inventory"
			coverage.Message = &message
			return nil, coverage
		}
		repositories = append(repositories, payload...)
		if len(payload) < 100 {
			break
		}
		if page == maxVendorPages {
			message := "GitHub repository inventory exceeded the pagination safety limit"
			coverage.Message = &message
			return nil, coverage
		}
	}
	coverage.ResourcesTotal = len(repositories)
	coverage.Status = "complete"
	if len(repositories) == 0 {
		return []protocol.DeployKey{}, coverage
	}

	type scanResult struct {
		credentials []protocol.DeployKey
		scanned     bool
	}
	jobs := make(chan githubRepository)
	results := make(chan scanResult, len(repositories))
	var wait sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for repository := range jobs {
				fullName := repository.FullName
				if fullName == "" {
					fullName = credentials["org"] + "/" + repository.Name
				}
				found := make([]protocol.DeployKey, 0)
				scanned := true
				for page := 1; page <= maxVendorPages; page++ {
					endpoint := "https://api.github.com/repos/" + org + "/" + url.PathEscape(repository.Name) + "/keys?per_page=100&page=" + strconv.Itoa(page)
					response, err := githubRequest(ctx, credentials["token"], endpoint)
					if err != nil {
						scanned = false
						break
					}
					var payload []githubDeployKey
					decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
					status := response.StatusCode
					response.Body.Close()
					if !successful(status) || decodeErr != nil {
						scanned = false
						break
					}
					for _, key := range payload {
						if key.Enabled != nil && !*key.Enabled {
							continue
						}
						access := "write"
						if key.ReadOnly {
							access = "read"
						}
						found = append(found, protocol.DeployKey{
							ID: strconv.FormatInt(key.ID, 10), Name: key.Title,
							Repository: fullName, Access: access, CreatedAt: stringPointer(key.CreatedAt),
							LastUsedAt: stringPointer(key.LastUsed), AddedBy: githubDeployKeyAddedBy(key.AddedBy),
						})
					}
					if len(payload) < 100 {
						break
					}
					if page == maxVendorPages {
						scanned = false
						break
					}
				}
				if !scanned {
					results <- scanResult{}
					continue
				}
				results <- scanResult{credentials: found, scanned: true}
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
	collected := make([]protocol.DeployKey, 0)
	for result := range results {
		if result.scanned {
			coverage.ResourcesScanned++
			collected = append(collected, result.credentials...)
		}
	}
	if coverage.ResourcesScanned != coverage.ResourcesTotal {
		coverage.Status = "partial"
		message := "Some repositories did not permit deploy-key inventory"
		coverage.Message = &message
	}
	sort.Slice(collected, func(left, right int) bool {
		if collected[left].Repository != collected[right].Repository {
			return collected[left].Repository < collected[right].Repository
		}
		if collected[left].Name != collected[right].Name {
			return collected[left].Name < collected[right].Name
		}
		return collected[left].ID < collected[right].ID
	})
	return collected, coverage
}

func GitHub(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token", "org"); err != nil {
		return nil, nil, err
	}
	org := url.PathEscape(credentials["org"])
	var members []protocol.Member
	collect := func(path, role string) error {
		for page := 1; page <= maxVendorPages; page++ {
			separator := "?"
			if containsQuestion(path) {
				separator = "&"
			}
			endpoint := "https://api.github.com/orgs/" + org + "/" + path + separator + "per_page=100&page=" + strconv.Itoa(page)
			response, err := githubRequest(ctx, credentials["token"], endpoint)
			if err != nil {
				return fmt.Errorf("GitHub collection failed: %w", err)
			}
			var payload []struct {
				ID    int64  `json:"id"`
				Login string `json:"login"`
			}
			decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
			response.Body.Close()
			if !successful(response.StatusCode) {
				return responseError("GitHub", response)
			}
			if decodeErr != nil {
				return errors.New("GitHub returned invalid member JSON")
			}
			for _, account := range payload {
				id := strconv.FormatInt(account.ID, 10)
				members = append(members, protocol.Member{ID: &id, Username: stringPointer(account.Login), Status: "active", Role: stringPointer(role)})
			}
			if len(payload) < 100 {
				return nil
			}
			if page == maxVendorPages {
				return errPaginationLimit
			}
		}
		return errPaginationLimit
	}
	if err := collect("members?role=admin", "owner"); err != nil {
		return nil, nil, err
	}
	if err := collect("members?role=member", "member"); err != nil {
		return nil, nil, err
	}
	if err := collect("outside_collaborators", "outside collaborator"); err != nil {
		return nil, nil, err
	}

	jobs := make(chan int)
	var wait sync.WaitGroup
	for worker := 0; worker < 6; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range jobs {
				username := members[index].Username
				if username == nil {
					continue
				}
				response, err := githubRequest(ctx, credentials["token"], "https://api.github.com/users/"+url.PathEscape(*username))
				if err != nil {
					continue
				}
				var profile struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				}
				decodeErr := decodeVendorJSON(response.Body, 1<<20, &profile)
				response.Body.Close()
				if successful(response.StatusCode) && decodeErr == nil {
					if profile.Name != "" {
						members[index].Name = stringPointer(profile.Name)
					}
					// GitHub exposes only the address the account owner chose to make
					// public. The authenticated-user email endpoint must not be used
					// here because it cannot reveal other organization members' mail.
					if profile.Email != "" {
						members[index].Email = stringPointer(profile.Email)
					}
				}
			}
		}()
	}
	for index := range members {
		jobs <- index
	}
	close(jobs)
	wait.Wait()
	if login, email, ok := githubTokenOwnerEmail(ctx, credentials["token"]); ok {
		for index := range members {
			if members[index].Username != nil && strings.EqualFold(*members[index].Username, login) {
				members[index].Email = stringPointer(email)
				break
			}
		}
	}
	return members, githubBillingSpend(ctx, credentials["token"], credentials["org"]), nil
}

func containsQuestion(value string) bool {
	for _, character := range value {
		if character == '?' {
			return true
		}
	}
	return false
}
