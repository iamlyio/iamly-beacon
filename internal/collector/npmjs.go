package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var npmRegistryBaseURL = "https://registry.npmjs.org"

// NPMJS inventories the roster returned by npm's organization API. npm
// exposes usernames and organization roles here, but not member email addresses.
func NPMJS(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token", "org"); err != nil {
		return nil, nil, err
	}
	endpoint, err := url.Parse(npmRegistryBaseURL + "/-/org/" + url.PathEscape(strings.TrimPrefix(credentials["org"], "@")) + "/user")
	if err != nil {
		return nil, nil, errors.New("npm organization collection endpoint is invalid")
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	request.Header.Set("Authorization", "Bearer "+credentials["token"])
	request.Header.Set("Accept", "application/json")
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return nil, nil, errors.New("npm organization collection could not be reached")
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return nil, nil, responseError("npm", response)
	}
	var roster map[string]string
	if err := decodeVendorJSON(response.Body, 16<<20, &roster); err != nil || roster == nil {
		return nil, nil, errors.New("npm organization collection returned invalid JSON")
	}
	if !memberPageFits(0, len(roster)) {
		return nil, nil, errMemberLimit
	}
	usernames := make([]string, 0, len(roster))
	for username := range roster {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)
	members := make([]protocol.Member, 0, len(usernames))
	for _, username := range usernames {
		role := strings.ToLower(strings.TrimSpace(roster[username]))
		if role == "" {
			role = "developer"
		}
		members = append(members, protocol.Member{
			ID: stringPointer(username), Username: stringPointer(username), Status: "active", Role: stringPointer(role),
		})
	}
	return members, nil, nil
}
