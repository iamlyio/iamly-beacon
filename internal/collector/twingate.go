package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var twingateNetworkPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

const twingateUsersQuery = `query BeaconUsers($after: String) {
  users(first: 100, after: $after) {
    pageInfo { hasNextPage endCursor }
    edges { node { id createdAt firstName lastName email state role type } }
  }
}`

type twingateUsersConnection struct {
	PageInfo struct {
		HasNextPage bool   `json:"hasNextPage"`
		EndCursor   string `json:"endCursor"`
	} `json:"pageInfo"`
	Edges []struct {
		Node struct {
			ID        string `json:"id"`
			CreatedAt string `json:"createdAt"`
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
			Email     string `json:"email"`
			State     string `json:"state"`
			Role      string `json:"role"`
			Type      string `json:"type"`
		} `json:"node"`
	} `json:"edges"`
}

// Twingate reads users through the network-specific GraphQL endpoint. The
// network value is restricted to one DNS label so credentials cannot redirect
// collection to an attacker-controlled host.
func Twingate(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "network", "apiToken"); err != nil {
		return nil, nil, err
	}
	network := strings.ToLower(credentials["network"])
	if !twingateNetworkPattern.MatchString(network) {
		return nil, nil, errors.New("Twingate network must be a network subdomain")
	}
	endpoint := "https://" + network + ".twingate.com/api/graphql/"
	members := make([]protocol.Member, 0)
	cursor := ""
	seen := map[string]bool{}
	for page := 1; page <= maxVendorPages; page++ {
		body, _ := json.Marshal(map[string]any{
			"query":     twingateUsersQuery,
			"variables": map[string]any{"after": stringPointer(cursor)},
		})
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-API-KEY", credentials["apiToken"])
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Twingate users collection could not be reached")
		}
		var payload struct {
			Data struct {
				Users *twingateUsersConnection `json:"users"`
			} `json:"data"`
			Errors []struct {
				Extensions struct {
					Code string `json:"code"`
				} `json:"extensions"`
			} `json:"errors"`
		}
		decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("Twingate", response)
		}
		if decodeErr != nil {
			return nil, nil, errors.New("Twingate users collection returned invalid JSON")
		}
		if len(payload.Errors) > 0 {
			return nil, nil, vendorAPIError("Twingate", payload.Errors[0].Extensions.Code)
		}
		if payload.Data.Users == nil {
			return nil, nil, errors.New("Twingate users collection returned invalid JSON")
		}
		if !memberPageFits(len(members), len(payload.Data.Users.Edges)) {
			return nil, nil, errMemberLimit
		}
		for _, edge := range payload.Data.Users.Edges {
			user := edge.Node
			status := "unknown"
			switch strings.ToUpper(user.State) {
			case "ACTIVE":
				status = "active"
			case "PENDING":
				status = "pending"
			case "DISABLED":
				status = "deactivated"
			}
			roleParts := make([]string, 0, 2)
			if user.Role != "" {
				roleParts = append(roleParts, strings.ToLower(user.Role))
			}
			if user.Type != "" {
				roleParts = append(roleParts, strings.ToLower(user.Type))
			}
			role := strings.Join(roleParts, " · ")
			members = append(members, protocol.Member{
				ID: stringPointer(user.ID), Email: stringPointer(user.Email),
				Name:   stringPointer(strings.TrimSpace(user.FirstName + " " + user.LastName)),
				Status: status, Role: stringPointer(role), CreatedAt: normalizedRFC3339Pointer(user.CreatedAt),
			})
		}
		pageInfo := payload.Data.Users.PageInfo
		if !pageInfo.HasNextPage {
			return members, nil, nil
		}
		if pageInfo.EndCursor == "" {
			return nil, nil, errors.New("Twingate returned invalid pagination data")
		}
		if seen[pageInfo.EndCursor] {
			return nil, nil, errRepeatedCursor
		}
		seen[pageInfo.EndCursor] = true
		cursor = pageInfo.EndCursor
	}
	return nil, nil, errPaginationLimit
}
