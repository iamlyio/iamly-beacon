package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const anthropicUsersURL = "https://api.anthropic.com/v1/organizations/users"

func normalizeAnthropicRole(role string) string {
	switch role {
	case "user", "claude_code_user", "developer", "billing", "admin", "managed", "owner", "membership_admin", "primary_owner":
		return role
	default:
		return "member"
	}
}

// Anthropic inventories current organization members through the Admin API.
// Cost reports are intentionally not queried: a member snapshot must not mix
// usage windows with an invoiced-spend claim.
func Anthropic(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "adminApiKey"); err != nil {
		return nil, nil, err
	}

	type anthropicUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Role    string `json:"role"`
		AddedAt string `json:"added_at"`
	}
	members := make([]protocol.Member, 0)
	cursor := ""
	seen := make(map[string]bool)
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(anthropicUsersURL)
		query := endpoint.Query()
		query.Set("limit", "100")
		if cursor != "" {
			query.Set("after_id", cursor)
		}
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("x-api-key", credentials["adminApiKey"])
		request.Header.Set("anthropic-version", "2023-06-01")
		request.Header.Set("Accept", "application/json")
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Anthropic users collection could not be reached")
		}
		var payload struct {
			Data    *[]anthropicUser `json:"data"`
			LastID  string           `json:"last_id"`
			HasMore bool             `json:"has_more"`
		}
		decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("Anthropic", response)
		}
		if decodeErr != nil || payload.Data == nil {
			return nil, nil, errors.New("Anthropic users collection returned invalid JSON")
		}
		if !memberPageFits(len(members), len(*payload.Data)) {
			return nil, nil, errMemberLimit
		}
		for _, user := range *payload.Data {
			members = append(members, protocol.Member{
				ID: stringPointer(user.ID), Email: stringPointer(user.Email), Name: stringPointer(user.Name),
				Status: "active", Role: stringPointer(normalizeAnthropicRole(user.Role)), CreatedAt: normalizedRFC3339Pointer(user.AddedAt),
			})
		}
		if !payload.HasMore {
			return members, nil, nil
		}
		if payload.LastID == "" {
			return nil, nil, errors.New("Anthropic users collection returned invalid pagination")
		}
		if seen[payload.LastID] {
			return nil, nil, errRepeatedCursor
		}
		seen[payload.LastID] = true
		cursor = payload.LastID
	}
	return nil, nil, errPaginationLimit
}
