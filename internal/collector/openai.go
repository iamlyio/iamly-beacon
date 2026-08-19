package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const openAIUsersURL = "https://api.openai.com/v1/organization/users"

func normalizeOpenAIRole(role string) string {
	switch role {
	case "owner", "reader":
		return role
	default:
		return "member"
	}
}

// OpenAI inventories current organization members with an Admin API key. The
// endpoint is read-only and does not expose an authoritative invoiced total,
// so this collector deliberately returns no observed spend.
func OpenAI(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "adminApiKey"); err != nil {
		return nil, nil, err
	}

	type openAIUser struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Role    string `json:"role"`
		AddedAt int64  `json:"added_at"`
	}
	members := make([]protocol.Member, 0)
	cursor := ""
	seen := make(map[string]bool)
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(openAIUsersURL)
		query := endpoint.Query()
		query.Set("limit", "100")
		if cursor != "" {
			query.Set("after", cursor)
		}
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+credentials["adminApiKey"])
		request.Header.Set("Accept", "application/json")
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("OpenAI users collection could not be reached")
		}
		var payload struct {
			Data    *[]openAIUser `json:"data"`
			LastID  string        `json:"last_id"`
			HasMore bool          `json:"has_more"`
		}
		decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("OpenAI", response)
		}
		if decodeErr != nil || payload.Data == nil {
			return nil, nil, errors.New("OpenAI users collection returned invalid JSON")
		}
		if !memberPageFits(len(members), len(*payload.Data)) {
			return nil, nil, errMemberLimit
		}
		for _, user := range *payload.Data {
			members = append(members, protocol.Member{
				ID: stringPointer(user.ID), Email: stringPointer(user.Email), Name: stringPointer(user.Name),
				Status: "active", Role: stringPointer(normalizeOpenAIRole(user.Role)), CreatedAt: normalizedUnixSecondsPointer(user.AddedAt),
			})
		}
		if !payload.HasMore {
			return members, nil, nil
		}
		if payload.LastID == "" {
			return nil, nil, errors.New("OpenAI users collection returned invalid pagination")
		}
		if seen[payload.LastID] {
			return nil, nil, errRepeatedCursor
		}
		seen[payload.LastID] = true
		cursor = payload.LastID
	}
	return nil, nil, errPaginationLimit
}
