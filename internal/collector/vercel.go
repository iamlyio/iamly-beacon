package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var vercelAPIBaseURL = "https://api.vercel.com"

type vercelMember struct {
	UID       string `json:"uid"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Confirmed bool   `json:"confirmed"`
	CreatedAt int64  `json:"createdAt"`
}

type vercelInvitation struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"createdAt"`
	Expired   bool   `json:"expired"`
}

func unixMillisPointer(milliseconds int64) *string {
	if milliseconds <= 0 || milliseconds > 253402300799999 {
		return nil
	}
	formatted := time.UnixMilli(milliseconds).UTC().Format(time.RFC3339)
	return &formatted
}

func normalizeVercelRole(role string) string {
	role = strings.ToLower(role)
	switch role {
	case "owner", "member", "developer", "security", "billing", "viewer", "viewer_for_plus", "contributor":
		return role
	default:
		return "member"
	}
}

// Vercel inventories the members of exactly one configured team.
func Vercel(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token", "teamId"); err != nil {
		return nil, nil, err
	}
	members := make([]protocol.Member, 0)
	var until int64
	seen := make(map[int64]bool)
	complete := false
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(vercelAPIBaseURL + "/v3/teams/" + url.PathEscape(credentials["teamId"]) + "/members")
		query := endpoint.Query()
		query.Set("limit", "100")
		if until > 0 {
			query.Set("until", strconv.FormatInt(until, 10))
		}
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+credentials["token"])
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Vercel team-members collection could not be reached")
		}
		var payload struct {
			Members          *[]vercelMember    `json:"members"`
			EmailInviteCodes []vercelInvitation `json:"emailInviteCodes"`
			Pagination       struct {
				HasNext bool  `json:"hasNext"`
				Next    int64 `json:"next"`
			} `json:"pagination"`
		}
		decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
		status := response.StatusCode
		response.Body.Close()
		if !successful(status) {
			return nil, nil, responseError("Vercel", response)
		}
		if decodeErr != nil || payload.Members == nil {
			return nil, nil, errors.New("Vercel team-members collection returned invalid JSON")
		}
		incoming := len(*payload.Members)
		if until == 0 {
			for _, invitation := range payload.EmailInviteCodes {
				if !invitation.Expired {
					incoming++
				}
			}
		}
		if !memberPageFits(len(members), incoming) {
			return nil, nil, errMemberLimit
		}
		for _, member := range *payload.Members {
			status := "active"
			if !member.Confirmed {
				status = "pending"
			}
			role := normalizeVercelRole(member.Role)
			members = append(members, protocol.Member{
				ID:        stringPointer(member.UID),
				Email:     stringPointer(member.Email),
				Name:      stringPointer(member.Name),
				Username:  stringPointer(member.Username),
				Status:    status,
				Role:      stringPointer(role),
				CreatedAt: unixMillisPointer(member.CreatedAt),
			})
		}
		// Vercel returns outstanding email invitations separately from team
		// members. They represent pending access and are returned only once;
		// do not duplicate them while paging the timestamp-based member list.
		if until == 0 {
			for _, invitation := range payload.EmailInviteCodes {
				if invitation.Expired {
					continue
				}
				members = append(members, protocol.Member{
					ID:        stringPointer(invitation.ID),
					Email:     stringPointer(invitation.Email),
					Status:    "pending",
					Role:      stringPointer(normalizeVercelRole(invitation.Role)),
					CreatedAt: unixMillisPointer(invitation.CreatedAt),
				})
			}
		}
		if !payload.Pagination.HasNext {
			complete = true
			break
		}
		next := payload.Pagination.Next
		if next <= 0 {
			return nil, nil, errors.New("Vercel returned invalid pagination metadata")
		}
		if seen[next] {
			return nil, nil, errRepeatedCursor
		}
		seen[next] = true
		until = next
	}
	if !complete {
		return nil, nil, errPaginationLimit
	}
	return members, nil, nil
}
