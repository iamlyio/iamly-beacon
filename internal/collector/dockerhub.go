package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var dockerHubAPIBaseURL = "https://hub.docker.com"

type dockerHubMember struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	PrimaryEmail   string `json:"primary_email"`
	FullName       string `json:"full_name"`
	Username       string `json:"username"`
	Role           string `json:"role"`
	Type           string `json:"type"`
	Status         string `json:"status"`
	DateJoined     string `json:"date_joined"`
	LastSeenAt     string `json:"last_seen_at"`
	LastLoggedInAt string `json:"last_logged_in_at"`
}

func dockerHubStatus(member dockerHubMember) string {
	if strings.Contains(strings.ToLower(member.Type), "invite") || strings.EqualFold(member.Status, "pending") || strings.EqualFold(member.Role, "invitee") {
		return "pending"
	}
	return "active"
}

func DockerHub(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "identifier", "secret", "org"); err != nil {
		return nil, nil, err
	}
	authBody, _ := json.Marshal(map[string]string{"identifier": credentials["identifier"], "secret": credentials["secret"]})
	authRequest, _ := http.NewRequestWithContext(ctx, http.MethodPost, dockerHubAPIBaseURL+"/v2/auth/token", bytes.NewReader(authBody))
	authRequest.Header.Set("Content-Type", "application/json")
	authRequest.Header.Set("Accept", "application/json")
	authResponse, err := doVendorRequest(ctx, authRequest)
	if err != nil {
		return nil, nil, errors.New("Docker Hub authentication could not be reached")
	}
	var authPayload struct {
		AccessToken string `json:"access_token"`
	}
	decodeErr := decodeVendorJSON(authResponse.Body, 1<<20, &authPayload)
	authResponse.Body.Close()
	if !successful(authResponse.StatusCode) {
		return nil, nil, responseError("Docker Hub", authResponse)
	}
	if decodeErr != nil || authPayload.AccessToken == "" {
		return nil, nil, errors.New("Docker Hub authentication returned invalid JSON")
	}

	members := make([]protocol.Member, 0)
	complete := false
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(dockerHubAPIBaseURL + "/v2/orgs/" + url.PathEscape(credentials["org"]) + "/members")
		query := endpoint.Query()
		query.Set("page", strconv.Itoa(page))
		query.Set("page_size", "100")
		query.Set("invites", "true")
		query.Set("type", "all")
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+authPayload.AccessToken)
		request.Header.Set("Accept", "application/json")
		response, requestErr := doVendorRequest(ctx, request)
		if requestErr != nil {
			return nil, nil, errors.New("Docker Hub member collection could not be reached")
		}
		type membersPage struct {
			Next    *string            `json:"next"`
			Results *[]dockerHubMember `json:"results"`
		}
		var raw json.RawMessage
		decodeErr = decodeVendorJSON(response.Body, 32<<20, &raw)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("Docker Hub", response)
		}
		var payload membersPage
		if decodeErr == nil {
			decodeErr = json.Unmarshal(raw, &payload)
		}
		// Docker's published OpenAPI currently describes the response as a
		// singleton array containing the pagination object, while the live API
		// commonly returns the pagination object directly. Accept both shapes.
		if decodeErr != nil || payload.Results == nil {
			var wrapped []membersPage
			if err := json.Unmarshal(raw, &wrapped); err != nil || len(wrapped) != 1 {
				decodeErr = errors.New("unexpected Docker Hub pagination shape")
			} else {
				payload = wrapped[0]
				decodeErr = nil
			}
		}
		if decodeErr != nil || payload.Results == nil {
			return nil, nil, errors.New("Docker Hub member collection returned invalid JSON")
		}
		if !memberPageFits(len(members), len(*payload.Results)) {
			return nil, nil, errMemberLimit
		}
		for _, member := range *payload.Results {
			email := member.PrimaryEmail
			if email == "" {
				email = member.Email
			}
			lastLogin := member.LastSeenAt
			if lastLogin == "" {
				lastLogin = member.LastLoggedInAt
			}
			id := member.ID
			if id == "" {
				id = member.Username
			}
			if id == "" {
				id = email
			}
			role := strings.ToLower(strings.TrimSpace(member.Role))
			members = append(members, protocol.Member{
				ID: stringPointer(id), Email: stringPointer(email), Name: stringPointer(member.FullName), Username: stringPointer(member.Username),
				Status: dockerHubStatus(member), Role: stringPointer(role), CreatedAt: normalizedRFC3339Pointer(member.DateJoined), LastLoginAt: normalizedRFC3339Pointer(lastLogin),
			})
		}
		if payload.Next == nil || *payload.Next == "" {
			complete = true
			break
		}
	}
	if !complete {
		return nil, nil, errPaginationLimit
	}
	return members, nil, nil
}
