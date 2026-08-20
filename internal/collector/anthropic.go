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

const anthropicUsersURL = "https://api.anthropic.com/v1/organizations/users"
const anthropicCostsURL = "https://api.anthropic.com/v1/organizations/cost_report"

func normalizeAnthropicRole(role string) string {
	switch role {
	case "user", "claude_code_user", "developer", "billing", "admin", "managed", "owner", "membership_admin", "primary_owner":
		return role
	default:
		return "member"
	}
}

func anthropicCurrentMonthSpend(ctx context.Context, adminAPIKey string) *protocol.Spend {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	cursor := ""
	seen := make(map[string]bool)
	totalCents := 0.0
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(anthropicCostsURL)
		query := endpoint.Query()
		query.Set("starting_at", start.Format(time.RFC3339))
		query.Set("ending_at", now.Format(time.RFC3339))
		query.Set("bucket_width", "1d")
		query.Set("limit", "31")
		if cursor != "" {
			query.Set("page", cursor)
		}
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("x-api-key", adminAPIKey)
		request.Header.Set("anthropic-version", "2023-06-01")
		request.Header.Set("Accept", "application/json")
		response, err := doVendorRequest(ctx, request)
		if err != nil || response == nil {
			return nil
		}
		var payload struct {
			Data []struct {
				Results []struct {
					Amount   string `json:"amount"`
					Currency string `json:"currency"`
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
				amount, err := strconv.ParseFloat(result.Amount, 64)
				if err != nil || amount < 0 || math.IsNaN(amount) || math.IsInf(amount, 0) || !strings.EqualFold(result.Currency, "USD") {
					return nil
				}
				totalCents += amount
			}
		}
		if !payload.HasMore {
			return &protocol.Spend{Amount: math.Round(totalCents*100) / 10000, Currency: "USD"}
		}
		if payload.NextPage == "" || seen[payload.NextPage] {
			return nil
		}
		seen[payload.NextPage] = true
		cursor = payload.NextPage
	}
	return nil
}

// Anthropic inventories current organization members and current-month API
// costs through the Admin API. Cost enrichment is best effort so a report
// permission or availability issue never discards the identity snapshot.
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
			return members, anthropicCurrentMonthSpend(ctx, credentials["adminApiKey"]), nil
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
