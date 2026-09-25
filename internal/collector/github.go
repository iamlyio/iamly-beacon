package collector

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
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
