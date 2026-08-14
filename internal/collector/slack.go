package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/reviam/beacon/internal/protocol"
)

type slackUser struct {
	ID                string `json:"id"`
	Deleted           bool   `json:"deleted"`
	IsBot             bool   `json:"is_bot"`
	RealName          string `json:"real_name"`
	IsAdmin           bool   `json:"is_admin"`
	IsOwner           bool   `json:"is_owner"`
	IsPrimaryOwner    bool   `json:"is_primary_owner"`
	IsRestricted      bool   `json:"is_restricted"`
	IsUltraRestricted bool   `json:"is_ultra_restricted"`
	Profile           struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	} `json:"profile"`
}

func slackRole(user slackUser) string {
	if user.IsPrimaryOwner {
		return "primary owner"
	}
	if user.IsOwner {
		return "owner"
	}
	if user.IsAdmin {
		return "admin"
	}
	if user.IsUltraRestricted {
		return "single-channel guest"
	}
	if user.IsRestricted {
		return "multi-channel guest"
	}
	return "member"
}

func slackGet(ctx context.Context, token, endpoint string, output any) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("Slack collection failed: %w", err)
	}
	defer response.Body.Close()
	var envelope struct {
		OK       bool            `json:"ok"`
		Error    string          `json:"error"`
		Members  json.RawMessage `json:"members"`
		Logins   json.RawMessage `json:"logins"`
		Billable json.RawMessage `json:"billable_info"`
		Metadata struct {
			Next string `json:"next_cursor"`
		} `json:"response_metadata"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(&envelope) != nil {
		return "", errors.New("Slack returned invalid JSON")
	}
	if !successful(response.StatusCode) {
		return "", responseError("Slack", response)
	}
	if !envelope.OK {
		return "", fmt.Errorf("Slack API error: %s", envelope.Error)
	}
	var raw json.RawMessage
	switch output.(type) {
	case *[]slackUser:
		raw = envelope.Members
	case *[]struct {
		UserID   string `json:"user_id"`
		DateLast int64  `json:"date_last"`
	}:
		raw = envelope.Logins
	case *map[string]struct {
		Active bool `json:"billing_active"`
	}:
		raw = envelope.Billable
	}
	if len(raw) > 0 && json.Unmarshal(raw, output) != nil {
		return "", errors.New("Slack returned invalid collection data")
	}
	return envelope.Metadata.Next, nil
}

func Slack(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "userToken"); err != nil {
		return nil, nil, err
	}
	token := credentials["userToken"]
	var users []slackUser
	cursor := ""
	seen := map[string]bool{}
	for {
		endpoint := "https://slack.com/api/users.list?limit=200"
		if cursor != "" {
			endpoint += "&cursor=" + url.QueryEscape(cursor)
		}
		var page []slackUser
		next, err := slackGet(ctx, token, endpoint, &page)
		if err != nil {
			return nil, nil, err
		}
		users = append(users, page...)
		if next == "" {
			break
		}
		if seen[next] {
			return nil, nil, errRepeatedCursor
		}
		seen[next] = true
		cursor = next
	}

	lastSeen := map[string]int64{}
	cursor = ""
	seen = map[string]bool{}
	for page := 0; page < 10; page++ {
		endpoint := "https://slack.com/api/team.accessLogs?limit=999"
		if cursor != "" {
			endpoint += "&cursor=" + url.QueryEscape(cursor)
		}
		var logs []struct {
			UserID   string `json:"user_id"`
			DateLast int64  `json:"date_last"`
		}
		next, err := slackGet(ctx, token, endpoint, &logs)
		if err != nil {
			break
		}
		for _, login := range logs {
			if login.DateLast > lastSeen[login.UserID] {
				lastSeen[login.UserID] = login.DateLast
			}
		}
		if next == "" || seen[next] {
			break
		}
		seen[next] = true
		cursor = next
	}

	billable := map[string]struct {
		Active bool `json:"billing_active"`
	}{}
	_, _ = slackGet(ctx, token, "https://slack.com/api/team.billableInfo?limit=200", &billable)
	members := make([]protocol.Member, 0, len(users))
	for _, user := range users {
		if user.IsBot || user.ID == "USLACKBOT" {
			continue
		}
		status := "active"
		if user.Deleted {
			status = "deactivated"
		}
		lastLogin := (*string)(nil)
		if timestamp := lastSeen[user.ID]; timestamp > 0 {
			formatted := unixISO(timestamp)
			lastLogin = &formatted
		}
		isBillable := !user.IsUltraRestricted
		if info, ok := billable[user.ID]; ok {
			isBillable = info.Active
		}
		members = append(members, protocol.Member{ID: stringPointer(user.ID), Email: stringPointer(user.Profile.Email), Name: stringPointer(user.RealName), Username: stringPointer(user.Profile.DisplayName), Status: status, Role: stringPointer(slackRole(user)), LastLoginAt: lastLogin, Billable: boolPointer(isBillable)})
	}
	return members, nil, nil
}

func unixISO(seconds int64) string { return time.Unix(seconds, 0).UTC().Format(time.RFC3339) }
