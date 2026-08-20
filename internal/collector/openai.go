package collector

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const openAIUsersURL = "https://api.openai.com/v1/organization/users"
const openAICostsURL = "https://api.openai.com/v1/organization/costs"

func normalizeOpenAIRole(role string) string {
	switch role {
	case "owner", "reader":
		return role
	default:
		return "member"
	}
}

func openAICurrentMonthSpend(ctx context.Context, adminAPIKey string) *protocol.Spend {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	cursor := ""
	seen := make(map[string]bool)
	total := 0.0
	currency := "USD"
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(openAICostsURL)
		query := endpoint.Query()
		query.Set("start_time", strconv.FormatInt(start.Unix(), 10))
		query.Set("end_time", strconv.FormatInt(now.Unix(), 10))
		query.Set("bucket_width", "1d")
		query.Set("limit", "31")
		if cursor != "" {
			query.Set("page", cursor)
		}
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+adminAPIKey)
		request.Header.Set("Accept", "application/json")
		response, err := doVendorRequest(ctx, request)
		if err != nil || response == nil {
			return nil
		}
		var payload struct {
			Data []struct {
				Results []struct {
					Amount *struct {
						Value    float64 `json:"value"`
						Currency string  `json:"currency"`
					} `json:"amount"`
				} `json:"results"`
			} `json:"data"`
			HasMore bool   `json:"has_more"`
			NextPage string `json:"next_page"`
		}
		decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
		response.Body.Close()
		if !successful(response.StatusCode) || decodeErr != nil {
			return nil
		}
		for _, bucket := range payload.Data {
			for _, result := range bucket.Results {
				if result.Amount == nil || result.Amount.Value < 0 || math.IsNaN(result.Amount.Value) || math.IsInf(result.Amount.Value, 0) {
					return nil
				}
				candidate := strings.ToUpper(strings.TrimSpace(result.Amount.Currency))
				if len(candidate) != 3 || currency != candidate {
					return nil
				}
				currency = candidate
				total += result.Amount.Value
			}
		}
		if !payload.HasMore {
			return &protocol.Spend{Amount: math.Round(total*10000) / 10000, Currency: currency}
		}
		if payload.NextPage == "" || seen[payload.NextPage] {
			return nil
		}
		seen[payload.NextPage] = true
		cursor = payload.NextPage
	}
	return nil
}

// OpenAI inventories current organization members and current-month API costs
// with the same read-only Admin API key. Cost enrichment is best effort so an
// unavailable report never discards a valid identity snapshot.
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
			return members, openAICurrentMonthSpend(ctx, credentials["adminApiKey"]), nil
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
