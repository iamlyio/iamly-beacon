package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var miroAPIBaseURL = "https://api.miro.com/v2"

type miroMember struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Active         *bool  `json:"active"`
	Role           string `json:"role"`
	License        string `json:"license"`
	LastActivityAt string `json:"lastActivityAt"`
	AdminRoles     []struct {
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"adminRoles"`
}

type miroMemberPage struct {
	Data   *[]miroMember `json:"data"`
	Cursor *string       `json:"cursor"`
	Size   *int          `json:"size"`
	Limit  *int          `json:"limit"`
}

// miroMembersPage is shared with the one-member connection probe so an error
// document returned with HTTP 200 cannot be mistaken for a successful roster.
func miroMembersPage(ctx context.Context, credentials map[string]string, cursor string, limit int) (miroMemberPage, error) {
	var payload miroMemberPage
	if err := require(credentials, "orgId", "token"); err != nil {
		return payload, err
	}
	endpoint, err := url.Parse(miroAPIBaseURL + "/orgs/" + url.PathEscape(credentials["orgId"]) + "/members")
	if err != nil {
		return payload, errors.New("Miro organization ID is invalid")
	}
	query := endpoint.Query()
	query.Set("limit", strconv.Itoa(limit))
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return payload, errors.New("Miro organization ID is invalid")
	}
	request.Header.Set("Authorization", "Bearer "+credentials["token"])
	request.Header.Set("Accept", "application/json")
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return payload, errors.New("Miro members collection could not be reached")
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return payload, responseError("Miro", response)
	}
	if decodeVendorJSON(response.Body, 1<<20, &payload) != nil || payload.Data == nil {
		return payload, errors.New("Miro members collection returned invalid JSON")
	}
	count := len(*payload.Data)
	if count > limit || (payload.Size != nil && *payload.Size != count) ||
		(payload.Limit != nil && (*payload.Limit < count || *payload.Limit < 1 || *payload.Limit > limit)) ||
		(count == 0 && payload.Cursor != nil && *payload.Cursor != "") {
		return payload, errors.New("Miro returned invalid pagination metadata")
	}
	for _, user := range *payload.Data {
		if strings.TrimSpace(user.ID) == "" || strings.TrimSpace(user.Email) == "" || user.Active == nil ||
			strings.TrimSpace(user.Role) == "" || strings.TrimSpace(user.License) == "" {
			return payload, errors.New("Miro members collection returned an invalid member")
		}
	}
	return payload, nil
}

func miroMemberRole(user miroMember) string {
	role := user.Role
	switch role {
	case "organization_internal_admin":
		role = "admin"
	case "organization_internal_user":
		role = "member"
	case "organization_external_user":
		role = "external"
	case "organization_team_guest_user":
		role = "guest"
	}
	parts := make([]string, 0, 2+len(user.AdminRoles))
	parts = append(parts, role, user.License)
	for _, adminRole := range user.AdminRoles {
		if name := strings.TrimSpace(adminRole.Name); name != "" {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, " · ")
}

// Miro reads only Enterprise organization membership, including deactivated
// users. License names are observations, not evidence of a billable seat or cost.
func Miro(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	members := make([]protocol.Member, 0)
	cursor := ""
	seen := make(map[string]bool)
	for range maxVendorPages {
		payload, err := miroMembersPage(ctx, credentials, cursor, 100)
		if err != nil {
			return nil, nil, err
		}
		users := *payload.Data
		if !memberPageFits(len(members), len(users)) {
			return nil, nil, errMemberLimit
		}
		for _, user := range users {
			status := "active"
			if !*user.Active {
				status = "deactivated"
			}
			members = append(members, protocol.Member{
				ID: stringPointer(user.ID), Email: stringPointer(user.Email),
				Status: status, Role: stringPointer(miroMemberRole(user)),
				LastLoginAt: normalizedRFC3339Pointer(user.LastActivityAt),
			})
		}
		// An explicitly empty response cursor is authoritative, even on a full
		// page. Without that optional field, request the last member ID until an
		// empty page rather than treating a short page as proof of completeness.
		if len(users) == 0 || (payload.Cursor != nil && *payload.Cursor == "") {
			return members, nil, nil
		}
		next := users[len(users)-1].ID
		if payload.Cursor != nil {
			next = *payload.Cursor
		}
		if seen[next] {
			return nil, nil, errRepeatedCursor
		}
		seen[next] = true
		cursor = next
	}
	return nil, nil, errPaginationLimit
}
