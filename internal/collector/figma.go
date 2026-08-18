package collector

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var figmaSCIMBaseURL = "https://www.figma.com/scim/v2"

type figmaEmail struct {
	Value   string `json:"value"`
	Primary any    `json:"primary"`
}

// Figma has historically rendered its email attribute as either a standard
// SCIM multi-valued array or a single object in its own examples. Accept both
// shapes without broadening the rest of the response schema.
type figmaEmails []figmaEmail

func (emails *figmaEmails) UnmarshalJSON(data []byte) error {
	var multiple []figmaEmail
	if err := json.Unmarshal(data, &multiple); err == nil {
		*emails = multiple
		return nil
	}
	var single figmaEmail
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	*emails = []figmaEmail{single}
	return nil
}

type figmaSCIMUser struct {
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Active      *bool       `json:"active"`
	Emails      figmaEmails `json:"emails"`
	Roles       []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"roles"`
	Meta struct {
		Created string `json:"created"`
	} `json:"meta"`
	FigmaExtension struct {
		Admin bool `json:"figmaAdmin"`
	} `json:"urn:ietf:params:scim:schemas:extension:figma:enterprise:2.0:User"`
}

func figmaUserEmail(user figmaSCIMUser) string {
	for _, email := range user.Emails {
		primary, _ := email.Primary.(bool)
		primaryText, _ := email.Primary.(string)
		if primary || strings.EqualFold(primaryText, "true") {
			return email.Value
		}
	}
	if len(user.Emails) > 0 {
		return user.Emails[0].Value
	}
	return user.UserName
}

func figmaUserRole(user figmaSCIMUser) string {
	if user.FigmaExtension.Admin {
		return "admin"
	}
	for _, role := range user.Roles {
		if strings.EqualFold(role.Type, "seatType") && role.Value != "" {
			value := strings.ToLower(role.Value)
			switch value {
			case "full", "dev", "collab", "view":
				return value
			}
		}
	}
	return "member"
}

// Figma uses its documented Enterprise SCIM API for authoritative user
// inventory. A personal token plus team ID cannot enumerate team members.
func Figma(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token", "tenantId"); err != nil {
		return nil, nil, err
	}
	members := make([]protocol.Member, 0)
	startIndex := 1
	complete := false
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(figmaSCIMBaseURL + "/" + url.PathEscape(credentials["tenantId"]) + "/Users")
		query := endpoint.Query()
		query.Set("count", "3000")
		query.Set("startIndex", strconv.Itoa(startIndex))
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+credentials["token"])
		request.Header.Set("Accept", "application/scim+json")
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Figma users collection could not be reached")
		}
		var payload struct {
			TotalResults int              `json:"totalResults"`
			Resources    *[]figmaSCIMUser `json:"Resources"`
		}
		decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
		status := response.StatusCode
		response.Body.Close()
		if !successful(status) {
			return nil, nil, responseError("Figma", response)
		}
		if decodeErr != nil || payload.TotalResults < 0 || payload.Resources == nil {
			return nil, nil, errors.New("Figma users collection returned invalid JSON")
		}
		if payload.TotalResults > maxCollectedMembers || !memberPageFits(len(members), len(*payload.Resources)) {
			return nil, nil, errMemberLimit
		}
		for _, user := range *payload.Resources {
			status := "active"
			if user.Active != nil && !*user.Active {
				status = "deactivated"
			}
			members = append(members, protocol.Member{
				ID:        stringPointer(user.ID),
				Email:     stringPointer(figmaUserEmail(user)),
				Name:      stringPointer(user.DisplayName),
				Username:  stringPointer(user.UserName),
				Status:    status,
				Role:      stringPointer(figmaUserRole(user)),
				CreatedAt: normalizedRFC3339Pointer(user.Meta.Created),
			})
		}
		nextIndex := startIndex + len(*payload.Resources)
		if nextIndex > payload.TotalResults {
			complete = true
			break
		}
		if len(*payload.Resources) == 0 {
			return nil, nil, errors.New("Figma returned invalid pagination metadata")
		}
		startIndex = nextIndex
	}
	if !complete {
		return nil, nil, errPaginationLimit
	}
	return members, nil, nil
}
