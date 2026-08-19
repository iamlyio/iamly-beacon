package collector

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const zoomAPIBaseURL = "https://api.zoom.us/v2"

func zoomAccessToken(ctx context.Context, credentials map[string]string) (string, error) {
	if err := require(credentials, "accountId", "clientId", "clientSecret"); err != nil {
		return "", err
	}
	endpoint, _ := url.Parse("https://zoom.us/oauth/token")
	query := endpoint.Query()
	query.Set("grant_type", "account_credentials")
	query.Set("account_id", credentials["accountId"])
	endpoint.RawQuery = query.Encode()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	basic := base64.StdEncoding.EncodeToString([]byte(credentials["clientId"] + ":" + credentials["clientSecret"]))
	request.Header.Set("Authorization", "Basic "+basic)
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return "", fmt.Errorf("Zoom token exchange failed: %w", err)
	}
	defer response.Body.Close()
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	decodeErr := decodeVendorJSON(response.Body, 1<<20, &payload)
	if !successful(response.StatusCode) {
		return "", responseError("Zoom", response)
	}
	if decodeErr != nil || payload.AccessToken == "" {
		return "", errors.New("Zoom token exchange returned invalid JSON")
	}
	return payload.AccessToken, nil
}

func Zoom(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	token, err := zoomAccessToken(ctx, credentials)
	if err != nil {
		return nil, nil, err
	}
	type zoomUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		FirstName     string `json:"first_name"`
		LastName      string `json:"last_name"`
		Status        string `json:"status"`
		RoleName      string `json:"role_name"`
		Type          int    `json:"type"`
		CreatedAt     string `json:"created_at"`
		LastLoginTime string `json:"last_login_time"`
	}
	statuses := []string{"active", "inactive", "pending"}
	members := make([]protocol.Member, 0)
	for _, requestedStatus := range statuses {
		cursor := ""
		seen := map[string]bool{}
		complete := false
		for page := 1; page <= maxVendorPages; page++ {
			endpoint, _ := url.Parse(zoomAPIBaseURL + "/users")
			query := endpoint.Query()
			query.Set("page_size", "300")
			query.Set("status", requestedStatus)
			if cursor != "" {
				query.Set("next_page_token", cursor)
			}
			endpoint.RawQuery = query.Encode()
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := doVendorRequest(ctx, request)
			if err != nil {
				return nil, nil, fmt.Errorf("Zoom users collection failed: %w", err)
			}
			var payload struct {
				Users []zoomUser `json:"users"`
				Next  string     `json:"next_page_token"`
			}
			decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
			response.Body.Close()
			if !successful(response.StatusCode) {
				return nil, nil, responseError("Zoom", response)
			}
			if decodeErr != nil {
				return nil, nil, errors.New("Zoom users collection returned invalid JSON")
			}
			for _, user := range payload.Users {
				status := "active"
				switch user.Status {
				case "inactive":
					status = "deactivated"
				case "pending":
					status = "pending"
				}
				role := user.RoleName
				if role == "" {
					role = "member"
				}
				name := strings.TrimSpace(user.FirstName + " " + user.LastName)
				members = append(members, protocol.Member{
					ID:          stringPointer(user.ID),
					Email:       stringPointer(user.Email),
					Name:        stringPointer(name),
					Status:      status,
					Role:        stringPointer(role),
					CreatedAt:   stringPointer(user.CreatedAt),
					LastLoginAt: stringPointer(user.LastLoginTime),
					Billable:    boolPointer(user.Type != 1),
				})
			}
			if payload.Next == "" {
				complete = true
				break
			}
			if seen[payload.Next] {
				return nil, nil, errRepeatedCursor
			}
			seen[payload.Next] = true
			cursor = payload.Next
		}
		if !complete {
			return nil, nil, errPaginationLimit
		}
	}
	return members, nil, nil
}
