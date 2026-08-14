package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/reviam/beacon/internal/protocol"
)

func githubRequest(ctx context.Context, token, endpoint string) (*http.Response, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return httpClient.Do(request)
}

func GitHub(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token", "org"); err != nil {
		return nil, nil, err
	}
	org := url.PathEscape(credentials["org"])
	var members []protocol.Member
	collect := func(path, role string) error {
		for page := 1; ; page++ {
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
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&payload)
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
		}
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
					Name string `json:"name"`
				}
				decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&profile)
				response.Body.Close()
				if successful(response.StatusCode) && decodeErr == nil {
					members[index].Name = stringPointer(profile.Name)
				}
			}
		}()
	}
	for index := range members {
		jobs <- index
	}
	close(jobs)
	wait.Wait()
	return members, nil, nil
}

func containsQuestion(value string) bool {
	for _, character := range value {
		if character == '?' {
			return true
		}
	}
	return false
}
