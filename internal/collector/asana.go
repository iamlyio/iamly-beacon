package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const asanaAPIBaseURL = "https://app.asana.com/api/1.0"

var asanaGIDPattern = regexp.MustCompile(`^[0-9]+$`)

// Asana inventories the current users of one workspace or organization. The
// standard API exposes current membership, not suspended/deprovisioned users,
// so returned records are normalized as active members.
func Asana(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token", "workspaceGid"); err != nil {
		return nil, nil, err
	}
	if !asanaGIDPattern.MatchString(credentials["workspaceGid"]) {
		return nil, nil, errors.New("Asana workspace GID is invalid")
	}

	type asanaUser struct {
		GID   string `json:"gid"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	members := make([]protocol.Member, 0)
	cursor := ""
	seen := make(map[string]bool)
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(asanaAPIBaseURL + "/users")
		query := endpoint.Query()
		query.Set("limit", "100")
		query.Set("opt_fields", "gid,name,email")
		query.Set("workspace", credentials["workspaceGid"])
		if cursor != "" {
			query.Set("offset", cursor)
		}
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+credentials["token"])
		request.Header.Set("Accept", "application/json")
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Asana users collection could not be reached")
		}
		var payload struct {
			Data     *[]asanaUser `json:"data"`
			NextPage *struct {
				Offset string `json:"offset"`
			} `json:"next_page"`
		}
		decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("Asana", response)
		}
		if decodeErr != nil || payload.Data == nil {
			return nil, nil, errors.New("Asana users collection returned invalid JSON")
		}
		if !memberPageFits(len(members), len(*payload.Data)) {
			return nil, nil, errMemberLimit
		}
		for _, user := range *payload.Data {
			members = append(members, protocol.Member{
				ID: stringPointer(user.GID), Email: stringPointer(user.Email), Name: stringPointer(user.Name),
				Status: "active", Role: stringPointer("member"),
			})
		}
		if payload.NextPage == nil {
			return members, nil, nil
		}
		if payload.NextPage.Offset == "" {
			return nil, nil, errors.New("Asana users collection returned invalid pagination")
		}
		if seen[payload.NextPage.Offset] {
			return nil, nil, errRepeatedCursor
		}
		seen[payload.NextPage.Offset] = true
		cursor = payload.NextPage.Offset
	}
	return nil, nil, errPaginationLimit
}
