package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var linearAPIURL = "https://api.linear.app/graphql"

const linearUsersQuery = `query BeaconUsers($first: Int!, $after: String) {
  users(first: $first, after: $after, includeDisabled: true) {
    nodes { id name displayName email active owner admin guest createdAt lastSeen }
    pageInfo { hasNextPage endCursor }
  }
}`

type linearUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Active      *bool  `json:"active"`
	Owner       bool   `json:"owner"`
	Admin       bool   `json:"admin"`
	Guest       bool   `json:"guest"`
	CreatedAt   string `json:"createdAt"`
	LastSeen    string `json:"lastSeen"`
}

func linearRole(user linearUser) string {
	if user.Owner {
		return "owner"
	}
	if user.Admin {
		return "admin"
	}
	if user.Guest {
		return "guest"
	}
	return "member"
}

// Linear uses one read-only GraphQL query and Relay cursor pagination.
func Linear(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "apiKey"); err != nil {
		return nil, nil, err
	}
	members := make([]protocol.Member, 0)
	cursor := ""
	seen := make(map[string]bool)
	complete := false
	for page := 1; page <= maxVendorPages; page++ {
		variables := map[string]any{"first": 100, "after": nil}
		if cursor != "" {
			variables["after"] = cursor
		}
		body, _ := json.Marshal(map[string]any{"query": linearUsersQuery, "variables": variables})
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, linearAPIURL, bytes.NewReader(body))
		request.Header.Set("Authorization", credentials["apiKey"])
		request.Header.Set("Content-Type", "application/json")
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Linear users collection could not be reached")
		}
		var payload struct {
			Data *struct {
				Users *struct {
					Nodes    []linearUser `json:"nodes"`
					PageInfo struct {
						HasNextPage bool    `json:"hasNextPage"`
						EndCursor   *string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"users"`
			} `json:"data"`
			Errors []struct {
				Extensions struct {
					Code string `json:"code"`
				} `json:"extensions"`
			} `json:"errors"`
		}
		decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
		status := response.StatusCode
		response.Body.Close()
		if !successful(status) {
			return nil, nil, responseError("Linear", response)
		}
		if decodeErr != nil {
			return nil, nil, errors.New("Linear users collection returned invalid JSON")
		}
		if len(payload.Errors) > 0 {
			return nil, nil, vendorAPIError("Linear", payload.Errors[0].Extensions.Code)
		}
		if payload.Data == nil || payload.Data.Users == nil {
			return nil, nil, errors.New("Linear users collection returned invalid JSON")
		}
		if !memberPageFits(len(members), len(payload.Data.Users.Nodes)) {
			return nil, nil, errMemberLimit
		}
		for _, user := range payload.Data.Users.Nodes {
			if user.Active == nil {
				return nil, nil, errors.New("Linear users collection returned invalid user data")
			}
			status := "active"
			if !*user.Active {
				status = "deactivated"
			}
			name := user.Name
			if name == "" {
				name = user.DisplayName
			}
			members = append(members, protocol.Member{
				ID:          stringPointer(user.ID),
				Email:       stringPointer(user.Email),
				Name:        stringPointer(name),
				Username:    stringPointer(user.DisplayName),
				Status:      status,
				Role:        stringPointer(linearRole(user)),
				CreatedAt:   normalizedRFC3339Pointer(user.CreatedAt),
				LastLoginAt: normalizedRFC3339Pointer(user.LastSeen),
			})
		}
		pageInfo := payload.Data.Users.PageInfo
		if !pageInfo.HasNextPage {
			complete = true
			break
		}
		if pageInfo.EndCursor == nil || *pageInfo.EndCursor == "" {
			return nil, nil, errors.New("Linear returned invalid pagination metadata")
		}
		next := *pageInfo.EndCursor
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
