package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var (
	bambooHRCompanyDomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	bambooHRAPIKey        = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

type bambooHREmployee struct {
	EmployeeID  string   `json:"employeeId"`
	FirstName   string   `json:"firstName"`
	LastName    string   `json:"lastName"`
	DisplayName string   `json:"displayName"`
	WorkEmail   string   `json:"workEmail"`
	JobTitle    string   `json:"jobTitleName"`
	Department  string   `json:"department"`
	Status      string   `json:"status"`
	HireDate    string   `json:"hireDate"`
	Restricted  []string `json:"_restrictedFields"`
}

func bambooHRMemberStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active":
		return "active"
	case "inactive":
		return "deactivated"
	default:
		return "unknown"
	}
}

func bambooHRRole(employee bambooHREmployee) string {
	title := strings.TrimSpace(employee.JobTitle)
	department := strings.TrimSpace(employee.Department)
	if title != "" && department != "" {
		return title + " · " + department
	}
	if title != "" {
		return title
	}
	if department != "" {
		return department
	}
	return "employee"
}

// ValidateBambooHRCredentials checks the values before they are persisted by
// guided setup and before a collection request is sent.
func ValidateBambooHRCredentials(credentials map[string]string) error {
	if err := require(credentials, "companyDomain", "apiKey"); err != nil {
		return err
	}
	companyDomain := strings.ToLower(strings.TrimSpace(credentials["companyDomain"]))
	if !bambooHRCompanyDomain.MatchString(companyDomain) {
		return errors.New("BambooHR company domain is invalid; enter only the subdomain, for example acme")
	}
	if !bambooHRAPIKey.MatchString(strings.TrimSpace(credentials["apiKey"])) {
		return errors.New("BambooHR API key must be a 40-character hexadecimal user API key")
	}
	return nil
}

// BambooHR reads the complete employee roster rather than the optional company
// directory. The directory excludes former employees and cannot be an
// authoritative lifecycle source for access reviews.
func BambooHR(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := ValidateBambooHRCredentials(credentials); err != nil {
		return nil, nil, err
	}
	companyDomain := strings.ToLower(strings.TrimSpace(credentials["companyDomain"]))

	members := make([]protocol.Member, 0)
	cursor := ""
	seen := map[string]bool{}
	for {
		endpoint := &url.URL{
			Scheme: "https",
			Host:   companyDomain + ".bamboohr.com",
			Path:   "/api/v1/employees",
		}
		query := endpoint.Query()
		query.Set("fields", "workEmail,hireDate,department")
		query.Set("page[limit]", "2500")
		if cursor != "" {
			query.Set("page[after]", cursor)
		}
		endpoint.RawQuery = query.Encode()

		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.SetBasicAuth(strings.TrimSpace(credentials["apiKey"]), "x")
		request.Header.Set("Accept", "application/json")
		response, err := doVendorRequest(ctx, request)
		if err != nil {
			return nil, nil, fmt.Errorf("BambooHR employee collection failed: %w", err)
		}
		var payload struct {
			Data []bambooHREmployee `json:"data"`
			Meta struct {
				Page struct {
					NextCursor string `json:"nextCursor"`
				} `json:"page"`
			} `json:"meta"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(&payload)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("BambooHR", response)
		}
		if decodeErr != nil {
			return nil, nil, errors.New("BambooHR employee collection returned invalid JSON")
		}
		for _, employee := range payload.Data {
			for _, field := range employee.Restricted {
				if field == "workEmail" {
					return nil, nil, errors.New("BambooHR API key cannot read workEmail for the complete employee roster")
				}
			}
			name := strings.TrimSpace(employee.DisplayName)
			if name == "" {
				name = strings.TrimSpace(employee.FirstName + " " + employee.LastName)
			}
			members = append(members, protocol.Member{
				ID:          stringPointer(employee.EmployeeID),
				Email:       stringPointer(strings.TrimSpace(employee.WorkEmail)),
				Name:        stringPointer(name),
				Status:      bambooHRMemberStatus(employee.Status),
				Role:        stringPointer(bambooHRRole(employee)),
				CreatedAt:   stringPointer(strings.TrimSpace(employee.HireDate)),
				LastLoginAt: nil,
			})
		}
		cursor = strings.TrimSpace(payload.Meta.Page.NextCursor)
		if cursor == "" {
			break
		}
		if seen[cursor] {
			return nil, nil, errRepeatedCursor
		}
		seen[cursor] = true
	}
	return members, nil, nil
}
