package collector

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var cloudflareAPIBaseURL = "https://api.cloudflare.com/client/v4"
var cloudflareAccountIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

const cloudflarePageSize = 50

type cloudflareRole struct {
	Name string `json:"name"`
}

type cloudflarePolicy struct {
	Access           string           `json:"access"`
	PermissionGroups []cloudflareRole `json:"permission_groups"`
}

type cloudflareMember struct {
	ID       string             `json:"id"`
	Email    string             `json:"email"`
	Status   string             `json:"status"`
	Roles    []cloudflareRole   `json:"roles"`
	Policies []cloudflarePolicy `json:"policies"`
	User     struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	} `json:"user"`
}

func cloudflareSubscriptionSpend(ctx context.Context, token, accountID string) *protocol.Spend {
	endpoint := cloudflareAPIBaseURL + "/accounts/" + url.PathEscape(accountID) + "/subscriptions"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := doVendorRequest(ctx, request)
	if err != nil || response == nil {
		return nil
	}
	var payload struct {
		Success bool `json:"success"`
		Result  []struct {
			Currency  string  `json:"currency"`
			Frequency string  `json:"frequency"`
			Price     float64 `json:"price"`
			State     string  `json:"state"`
		} `json:"result"`
	}
	decodeErr := decodeVendorJSON(response.Body, 16<<20, &payload)
	response.Body.Close()
	if !successful(response.StatusCode) || decodeErr != nil || !payload.Success {
		return nil
	}
	total := 0.0
	currency := ""
	for _, subscription := range payload.Result {
		state := strings.ToLower(strings.TrimSpace(subscription.State))
		if state == "cancelled" || state == "failed" || state == "expired" || subscription.Price == 0 {
			continue
		}
		if subscription.Price < 0 || math.IsNaN(subscription.Price) || math.IsInf(subscription.Price, 0) {
			return nil
		}
		candidate := strings.ToUpper(strings.TrimSpace(subscription.Currency))
		if len(candidate) != 3 || (currency != "" && currency != candidate) {
			return nil
		}
		currency = candidate
		switch strings.ToLower(strings.TrimSpace(subscription.Frequency)) {
		case "weekly":
			total += subscription.Price * 52 / 12
		case "monthly", "":
			total += subscription.Price
		case "quarterly":
			total += subscription.Price / 3
		case "yearly":
			total += subscription.Price / 12
		default:
			return nil
		}
	}
	if currency == "" {
		return nil
	}
	return &protocol.Spend{Amount: math.Round(total*10000) / 10000, Currency: currency}
}

func cloudflareMemberStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "accepted", "member":
		return "active"
	case "pending", "invited":
		return "pending"
	case "rejected":
		return "deactivated"
	default:
		return "unknown"
	}
}

func cloudflareMemberRole(member cloudflareMember) *string {
	names := make(map[string]struct{})
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 120 || len(names) >= 32 {
			return
		}
		names[value] = struct{}{}
	}
	for _, role := range member.Roles {
		add(role.Name)
	}
	for _, policy := range member.Policies {
		if strings.EqualFold(policy.Access, "deny") {
			continue
		}
		for _, group := range policy.PermissionGroups {
			add(group.Name)
		}
	}
	if len(names) == 0 {
		return stringPointer("member")
	}
	roles := make([]string, 0, len(names))
	for name := range names {
		roles = append(roles, name)
	}
	sort.Slice(roles, func(left, right int) bool {
		privilege := func(value string) int {
			value = strings.ToLower(value)
			switch {
			case strings.Contains(value, "super administrator"):
				return 0
			case strings.Contains(value, "administrator") || strings.Contains(value, "owner"):
				return 1
			case strings.Contains(value, " write") || strings.Contains(value, " edit"):
				return 2
			default:
				return 3
			}
		}
		leftPrivilege, rightPrivilege := privilege(roles[left]), privilege(roles[right])
		if leftPrivilege != rightPrivilege {
			return leftPrivilege < rightPrivilege
		}
		return roles[left] < roles[right]
	})
	// The control plane bounds roles at 500 characters. Four Cloudflare role
	// or permission-group names preserve useful privilege evidence while
	// keeping the normalized account record compact.
	if len(roles) > 4 {
		roles = roles[:4]
	}
	return stringPointer(strings.Join(roles, ", "))
}

// Cloudflare inventories account members using an account-scoped API token
// with Account Settings Read. The token never leaves Beacon's local vault.
func Cloudflare(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := require(credentials, "token", "accountId"); err != nil {
		return nil, nil, err
	}
	if !cloudflareAccountIDPattern.MatchString(credentials["accountId"]) {
		return nil, nil, errors.New("Cloudflare account ID must be 32 lowercase hexadecimal characters")
	}
	members := make([]protocol.Member, 0)
	complete := false
	for page := 1; page <= maxVendorPages; page++ {
		endpoint, _ := url.Parse(cloudflareAPIBaseURL + "/accounts/" + url.PathEscape(credentials["accountId"]) + "/members")
		query := endpoint.Query()
		query.Set("page", strconv.Itoa(page))
		query.Set("per_page", strconv.Itoa(cloudflarePageSize))
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+credentials["token"])
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, errors.New("Cloudflare account-members collection could not be reached")
		}
		var payload struct {
			Success    bool                `json:"success"`
			Result     *[]cloudflareMember `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				TotalCount int `json:"total_count"`
			} `json:"result_info"`
		}
		decodeErr := decodeVendorJSON(response.Body, 32<<20, &payload)
		status := response.StatusCode
		response.Body.Close()
		if !successful(status) {
			return nil, nil, responseError("Cloudflare", response)
		}
		if decodeErr != nil || !payload.Success || payload.Result == nil {
			return nil, nil, errors.New("Cloudflare account-members collection returned invalid JSON")
		}
		if payload.ResultInfo.Page != 0 && payload.ResultInfo.Page != page {
			return nil, nil, errors.New("Cloudflare returned invalid pagination metadata")
		}
		if !memberPageFits(len(members), len(*payload.Result)) {
			return nil, nil, errMemberLimit
		}
		for _, member := range *payload.Result {
			id := member.ID
			if id == "" {
				id = member.User.ID
			}
			email := member.Email
			if email == "" {
				email = member.User.Email
			}
			name := strings.TrimSpace(member.User.FirstName + " " + member.User.LastName)
			members = append(members, protocol.Member{
				ID:     stringPointer(id),
				Email:  stringPointer(email),
				Name:   stringPointer(name),
				Status: cloudflareMemberStatus(member.Status),
				Role:   cloudflareMemberRole(member),
			})
		}
		if payload.ResultInfo.TotalCount > 0 {
			if len(members) >= payload.ResultInfo.TotalCount {
				complete = true
				break
			}
			if len(*payload.Result) == 0 {
				return nil, nil, errors.New("Cloudflare returned invalid pagination metadata")
			}
		} else if len(*payload.Result) < cloudflarePageSize {
			complete = true
			break
		}
	}
	if !complete {
		return nil, nil, errPaginationLimit
	}
	return members, cloudflareSubscriptionSpend(ctx, credentials["token"], credentials["accountId"]), nil
}
