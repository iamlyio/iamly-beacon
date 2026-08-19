package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var notionAPIBaseURL = "https://api.notion.com/v1"

type notionUser struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Person *struct {
		Email string `json:"email"`
	} `json:"person"`
}

// Notion inventories every user visible to an internal integration. Notion's
// user-list response does not expose suspension, role, billing, or activity
// metadata, so the collector deliberately does not infer those values.
func Notion(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token"); err != nil {
		return nil, nil, err
	}

	members := make([]protocol.Member, 0)
	cursor := ""
	seen := make(map[string]bool)
	complete := false
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(notionAPIBaseURL + "/users")
		query := endpoint.Query()
		query.Set("page_size", "100")
		if cursor != "" {
			query.Set("start_cursor", cursor)
		}
		endpoint.RawQuery = query.Encode()

		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+credentials["token"])
		request.Header.Set("Notion-Version", "2026-03-11")
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Notion users collection could not be reached")
		}
		var payload struct {
			Object     string       `json:"object"`
			Results    []notionUser `json:"results"`
			HasMore    bool         `json:"has_more"`
			NextCursor *string      `json:"next_cursor"`
		}
		decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
		status := response.StatusCode
		response.Body.Close()
		if !successful(status) {
			return nil, nil, responseError("Notion", response)
		}
		if decodeErr != nil || payload.Object != "list" {
			return nil, nil, errors.New("Notion users collection returned invalid JSON")
		}
		if !memberPageFits(len(members), len(payload.Results)) {
			return nil, nil, errMemberLimit
		}
		for _, user := range payload.Results {
			role := user.Type
			if role != "person" && role != "bot" {
				role = "member"
			}
			email := ""
			if user.Person != nil {
				email = user.Person.Email
			}
			members = append(members, protocol.Member{
				ID:     stringPointer(user.ID),
				Email:  stringPointer(email),
				Name:   stringPointer(user.Name),
				Status: "active",
				Role:   stringPointer(role),
			})
		}
		if !payload.HasMore {
			complete = true
			break
		}
		if payload.NextCursor == nil || *payload.NextCursor == "" {
			return nil, nil, errors.New("Notion returned invalid pagination metadata")
		}
		next := *payload.NextCursor
		if seen[next] {
			return nil, nil, errRepeatedCursor
		}
		seen[next] = true
		cursor = next
	}
	if !complete {
		return nil, nil, errPaginationLimit
	}
	return members, nil, nil
}
