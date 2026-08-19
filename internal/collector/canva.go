package collector

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const canvaSCIMUsersURL = "https://www.canva.com/_scim/v2/Users"

func normalizeCanvaRole(role string) string {
	switch role {
	case "Member":
		return "member"
	case "Teacher", "Staff", "Admin", "Template-designer", "Aide", "Administrator", "School administrator", "School", "Tenant", "Faculty":
		// Canva documents that every non-Member SCIM role maps to its
		// Brand Designer product role. Reporting "Admin" here would
		// incorrectly imply administrative privileges.
		return "brand designer"
	default:
		return "member"
	}
}

// Canva inventories users from the stable SCIM API. This endpoint includes
// inactive accounts and is preferred over Canva's preview Admin API.
func Canva(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token"); err != nil {
		return nil, nil, err
	}

	type canvaUser struct {
		ID          string `json:"id"`
		UserName    string `json:"userName"`
		DisplayName string `json:"displayName"`
		Active      bool   `json:"active"`
		Role        string `json:"role"`
		Meta        struct {
			Created string `json:"created"`
		} `json:"meta"`
		Emails []struct {
			Value   string `json:"value"`
			Primary bool   `json:"primary"`
		} `json:"emails"`
	}
	members := make([]protocol.Member, 0)
	startIndex := 1
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(canvaSCIMUsersURL)
		query := endpoint.Query()
		query.Set("startIndex", strconv.Itoa(startIndex))
		query.Set("count", "10")
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+credentials["token"])
		request.Header.Set("Accept", "application/scim+json")
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Canva users collection could not be reached")
		}
		var payload struct {
			TotalResults int          `json:"totalResults"`
			StartIndex   int          `json:"startIndex"`
			ItemsPerPage int          `json:"itemsPerPage"`
			Resources    *[]canvaUser `json:"resources"`
		}
		decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("Canva", response)
		}
		if decodeErr != nil || payload.TotalResults < 0 || payload.Resources == nil {
			return nil, nil, errors.New("Canva users collection returned invalid JSON")
		}
		if !memberPageFits(len(members), len(*payload.Resources)) {
			return nil, nil, errMemberLimit
		}
		for _, user := range *payload.Resources {
			email := ""
			for _, candidate := range user.Emails {
				if email == "" || candidate.Primary {
					email = candidate.Value
				}
				if candidate.Primary {
					break
				}
			}
			status := "active"
			if !user.Active {
				status = "deactivated"
			}
			members = append(members, protocol.Member{
				ID: stringPointer(user.ID), Email: stringPointer(email), Name: stringPointer(user.DisplayName),
				Username: stringPointer(user.UserName), Status: status, Role: stringPointer(normalizeCanvaRole(user.Role)),
				CreatedAt: normalizedRFC3339Pointer(user.Meta.Created),
			})
		}
		if len(members) >= payload.TotalResults {
			return members, nil, nil
		}
		if len(*payload.Resources) == 0 {
			return nil, nil, errors.New("Canva users collection returned invalid pagination")
		}
		startIndex += len(*payload.Resources)
	}
	return nil, nil, errPaginationLimit
}
