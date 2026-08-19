package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

func tailscaleAccessToken(ctx context.Context, credentials map[string]string) (string, error) {
	if err := require(credentials, "clientId", "clientSecret"); err != nil {
		return "", err
	}
	form := url.Values{
		"client_id":     {credentials["clientId"]},
		"client_secret": {credentials["clientSecret"]},
		"grant_type":    {"client_credentials"},
		"scope":         {"users:read"},
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return "", errors.New("Tailscale token exchange could not be reached")
	}
	defer response.Body.Close()
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	decodeErr := decodeVendorJSON(response.Body, 1<<20, &payload)
	if !successful(response.StatusCode) {
		return "", responseError("Tailscale", response)
	}
	if decodeErr != nil || payload.AccessToken == "" {
		return "", errors.New("Tailscale token exchange returned invalid JSON")
	}
	return payload.AccessToken, nil
}

// Tailscale lists every user in the OAuth client's own tailnet using the
// vendor-supported "-" alias and a short-lived users:read token.
func Tailscale(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	token, err := tailscaleAccessToken(ctx, credentials)
	if err != nil {
		return nil, nil, err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.tailscale.com/api/v2/tailnet/-/users?type=all", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return nil, nil, errors.New("Tailscale users collection could not be reached")
	}
	defer response.Body.Close()
	type tailscaleUser struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		LoginName   string `json:"loginName"`
		Created     string `json:"created"`
		Type        string `json:"type"`
		Role        string `json:"role"`
		Status      string `json:"status"`
		LastSeen    string `json:"lastSeen"`
	}
	var payload struct {
		Users *[]tailscaleUser `json:"users"`
	}
	decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
	if !successful(response.StatusCode) {
		return nil, nil, responseError("Tailscale", response)
	}
	if decodeErr != nil || payload.Users == nil {
		return nil, nil, errors.New("Tailscale users collection returned invalid JSON")
	}
	if !memberPageFits(0, len(*payload.Users)) {
		return nil, nil, errMemberLimit
	}
	members := make([]protocol.Member, 0, len(*payload.Users))
	for _, user := range *payload.Users {
		status := "unknown"
		switch strings.ToLower(user.Status) {
		case "active", "idle":
			status = "active"
		case "suspended", "over-billing-limit":
			status = "suspended"
		case "needs-approval", "needs_approval", "pending":
			status = "pending"
		}
		role := user.Role
		if strings.EqualFold(user.Type, "shared") {
			if role == "" {
				role = "shared"
			} else {
				role += " · shared"
			}
		}
		members = append(members, protocol.Member{
			ID: stringPointer(user.ID), Email: stringPointer(user.LoginName), Name: stringPointer(user.DisplayName),
			Username: stringPointer(user.LoginName), Status: status, Role: stringPointer(role),
			CreatedAt: normalizedRFC3339Pointer(user.Created), LastLoginAt: normalizedRFC3339Pointer(user.LastSeen),
		})
	}
	return members, nil, nil
}
