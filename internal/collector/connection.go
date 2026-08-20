package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type ConnectionErrorCode string

const (
	CredentialsRejected  ConnectionErrorCode = "credentials_rejected"
	PermissionDenied     ConnectionErrorCode = "permission_denied"
	InvalidConfiguration ConnectionErrorCode = "invalid_configuration"
	RateLimited          ConnectionErrorCode = "rate_limited"
	VendorUnavailable    ConnectionErrorCode = "vendor_unavailable"
	TimedOut             ConnectionErrorCode = "timed_out"
	UnexpectedResponse   ConnectionErrorCode = "unexpected_response"
)

type ConnectionError struct {
	Code ConnectionErrorCode
}

func (e ConnectionError) Error() string { return string(e.Code) }

func ConnectionErrorCodeOf(err error) ConnectionErrorCode {
	var connectionError ConnectionError
	if errors.As(err, &connectionError) {
		return connectionError.Code
	}
	return UnexpectedResponse
}

var ConnectionTesters = map[string]ConnectionTester{
	"anthropic":  testAnthropicConnection,
	"asana":      testAsanaConnection,
	"bamboohr":   testBambooHRConnection,
	"canva":      testCanvaConnection,
	"cloudflare": testCloudflareConnection,
	"dockerhub":  testDockerHubConnection,
	"figma":      testFigmaConnection,
	"gcp":        testGCPConnection,
	"github":     testGitHubConnection,
	"google":     testGoogleConnection,
	"linear":     testLinearConnection,
	"notion":     testNotionConnection,
	"npmjs":      testNPMConnection,
	"openai":     testOpenAIConnection,
	"slack":      testSlackConnection,
	"tailscale":  testTailscaleConnection,
	"twingate":   testTwingateConnection,
	"vercel":     testVercelConnection,
	"zoom":       testZoomConnection,
}

func TestConnection(ctx context.Context, platform string, credentials map[string]string) error {
	tester, ok := ConnectionTesters[platform]
	if !ok {
		return ConnectionError{Code: InvalidConfiguration}
	}
	return normalizeConnectionError(ctx, tester(ctx, credentials))
}

func normalizeConnectionError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var connectionError ConnectionError
	if errors.As(err, &connectionError) {
		return connectionError
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return ConnectionError{Code: TimedOut}
	}
	var statusError vendorHTTPError
	if errors.As(err, &statusError) {
		return connectionHTTPError(statusError.status)
	}
	var codeError vendorCodeError
	if errors.As(err, &codeError) {
		switch codeError.code {
		case "invalid_auth", "account_inactive", "token_revoked", "not_authed", "invalid_token",
			"authentication_error", "unauthenticated", "unauthorized":
			return ConnectionError{Code: CredentialsRejected}
		case "missing_scope", "not_allowed", "forbidden", "permission_denied", "access_denied":
			return ConnectionError{Code: PermissionDenied}
		case "ratelimited", "rate_limited":
			return ConnectionError{Code: RateLimited}
		default:
			return ConnectionError{Code: UnexpectedResponse}
		}
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "missing local credential"),
		strings.Contains(message, " is invalid"), strings.Contains(message, "not valid"),
		strings.Contains(message, " must be"),
		strings.Contains(message, "must use"), strings.Contains(message, "enter only"):
		return ConnectionError{Code: InvalidConfiguration}
	case strings.Contains(message, "could not be reached"), strings.Contains(message, "failed:"):
		return ConnectionError{Code: VendorUnavailable}
	case errors.Is(err, context.Canceled):
		return ConnectionError{Code: VendorUnavailable}
	default:
		return ConnectionError{Code: UnexpectedResponse}
	}
}

func connectionHTTPError(status int) error {
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusUnprocessableEntity:
		return ConnectionError{Code: InvalidConfiguration}
	case http.StatusUnauthorized:
		return ConnectionError{Code: CredentialsRejected}
	case http.StatusForbidden:
		return ConnectionError{Code: PermissionDenied}
	case http.StatusTooManyRequests:
		return ConnectionError{Code: RateLimited}
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return ConnectionError{Code: TimedOut}
	default:
		if status >= 500 {
			return ConnectionError{Code: VendorUnavailable}
		}
		return ConnectionError{Code: UnexpectedResponse}
	}
}

func probeRequest(ctx context.Context, platform string, request *http.Request) error {
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return ConnectionError{Code: TimedOut}
		}
		return ConnectionError{Code: VendorUnavailable}
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return connectionHTTPError(response.StatusCode)
	}
	var payload json.RawMessage
	if decodeVendorJSON(response.Body, 1<<20, &payload) != nil || len(payload) == 0 {
		return ConnectionError{Code: UnexpectedResponse}
	}
	return nil
}

func bearerProbe(ctx context.Context, platform, endpoint, token, accept string) error {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	return probeRequest(ctx, platform, request)
}

func testAnthropicConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "adminApiKey"); err != nil {
		return err
	}
	endpoint := anthropicUsersURL + "?limit=1"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("x-api-key", credentials["adminApiKey"])
	request.Header.Set("anthropic-version", "2023-06-01")
	request.Header.Set("Accept", "application/json")
	return probeRequest(ctx, "Anthropic", request)
}

func testAsanaConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "token", "workspaceGid"); err != nil {
		return err
	}
	if !asanaGIDPattern.MatchString(credentials["workspaceGid"]) {
		return errors.New("Asana workspace GID is invalid")
	}
	endpoint, _ := url.Parse(asanaAPIBaseURL + "/users")
	query := endpoint.Query()
	query.Set("limit", "1")
	query.Set("opt_fields", "gid")
	query.Set("workspace", credentials["workspaceGid"])
	endpoint.RawQuery = query.Encode()
	return bearerProbe(ctx, "Asana", endpoint.String(), credentials["token"], "application/json")
}

func testBambooHRConnection(ctx context.Context, credentials map[string]string) error {
	if err := ValidateBambooHRCredentials(credentials); err != nil {
		return err
	}
	endpoint := &url.URL{Scheme: "https", Host: strings.ToLower(strings.TrimSpace(credentials["companyDomain"])) + ".bamboohr.com", Path: "/api/v1/employees"}
	query := endpoint.Query()
	query.Set("fields", "workEmail")
	query.Set("page[limit]", "1")
	endpoint.RawQuery = query.Encode()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	request.SetBasicAuth(strings.TrimSpace(credentials["apiKey"]), "x")
	request.Header.Set("Accept", "application/json")
	return probeRequest(ctx, "BambooHR", request)
}

func testCanvaConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "token"); err != nil {
		return err
	}
	return bearerProbe(ctx, "Canva", canvaSCIMUsersURL+"?count=1&startIndex=1", credentials["token"], "application/scim+json")
}

func testCloudflareConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "token", "accountId"); err != nil {
		return err
	}
	if !cloudflareAccountIDPattern.MatchString(credentials["accountId"]) {
		return errors.New("Cloudflare account ID must be 32 lowercase hexadecimal characters")
	}
	endpoint := cloudflareAPIBaseURL + "/accounts/" + url.PathEscape(credentials["accountId"]) + "/members?page=1&per_page=1"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+credentials["token"])
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return ConnectionError{Code: VendorUnavailable}
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return connectionHTTPError(response.StatusCode)
	}
	var payload struct {
		Success bool `json:"success"`
	}
	if decodeVendorJSON(response.Body, 1<<20, &payload) != nil || !payload.Success {
		return ConnectionError{Code: UnexpectedResponse}
	}
	return nil
}

func dockerHubProbeToken(ctx context.Context, credentials map[string]string) (string, error) {
	if err := require(credentials, "identifier", "secret", "org"); err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{"identifier": credentials["identifier"], "secret": credentials["secret"]})
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, dockerHubAPIBaseURL+"/v2/auth/token", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return "", ConnectionError{Code: VendorUnavailable}
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return "", connectionHTTPError(response.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if decodeVendorJSON(response.Body, 1<<20, &payload) != nil || payload.AccessToken == "" {
		return "", ConnectionError{Code: UnexpectedResponse}
	}
	return payload.AccessToken, nil
}

func testDockerHubConnection(ctx context.Context, credentials map[string]string) error {
	token, err := dockerHubProbeToken(ctx, credentials)
	if err != nil {
		return err
	}
	endpoint := dockerHubAPIBaseURL + "/v2/orgs/" + url.PathEscape(credentials["org"]) + "/members?invites=true&page=1&page_size=1&type=all"
	return bearerProbe(ctx, "Docker Hub", endpoint, token, "application/json")
}

func testFigmaConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "token", "tenantId"); err != nil {
		return err
	}
	endpoint := figmaSCIMBaseURL + "/" + url.PathEscape(credentials["tenantId"]) + "/Users?count=1&startIndex=1"
	return bearerProbe(ctx, "Figma", endpoint, credentials["token"], "application/scim+json")
}

func testGCPConnection(ctx context.Context, credentials map[string]string) error {
	token, err := gcpAccessToken(ctx, credentials)
	if err != nil {
		return err
	}
	endpoint, _ := url.Parse("https://cloudasset.googleapis.com/v1/" + credentials["resourceScope"] + ":searchAllIamPolicies")
	query := endpoint.Query()
	query.Set("pageSize", "1")
	query.Set("query", "memberTypes:(user OR serviceAccount)")
	endpoint.RawQuery = query.Encode()
	return bearerProbe(ctx, "GCP", endpoint.String(), token, "application/json")
}

func testGitHubConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "token", "org"); err != nil {
		return err
	}
	endpoint := "https://api.github.com/user/memberships/orgs/" + url.PathEscape(credentials["org"])
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+credentials["token"])
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return probeRequest(ctx, "GitHub", request)
}

func testGoogleConnection(ctx context.Context, credentials map[string]string) error {
	token, err := googleAccessToken(ctx, credentials)
	if err != nil {
		return err
	}
	endpoint := "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=1"
	return bearerProbe(ctx, "Google", endpoint, token, "application/json")
}

func testLinearConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "apiKey"); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"query": `query BeaconConnectionTest { users(first: 1) { nodes { id } } }`})
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, linearAPIURL, bytes.NewReader(body))
	request.Header.Set("Authorization", credentials["apiKey"])
	request.Header.Set("Content-Type", "application/json")
	return graphqlProbe(ctx, "Linear", request, "users")
}

func testNotionConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "token"); err != nil {
		return err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, notionAPIBaseURL+"/users?page_size=1", nil)
	request.Header.Set("Authorization", "Bearer "+credentials["token"])
	request.Header.Set("Notion-Version", "2026-03-11")
	return probeRequest(ctx, "Notion", request)
}

func testNPMConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "token", "org"); err != nil {
		return err
	}
	// npm's organization roster endpoint is not paginated. The bounded whoami
	// endpoint proves token authentication without downloading the full roster.
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, npmRegistryBaseURL+"/-/whoami", nil)
	request.Header.Set("Authorization", "Bearer "+credentials["token"])
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return ConnectionError{Code: VendorUnavailable}
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return connectionHTTPError(response.StatusCode)
	}
	var payload struct {
		Username string `json:"username"`
	}
	if decodeVendorJSON(response.Body, 64<<10, &payload) != nil || payload.Username == "" {
		return ConnectionError{Code: UnexpectedResponse}
	}
	return nil
}

func testOpenAIConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "adminApiKey"); err != nil {
		return err
	}
	return bearerProbe(ctx, "OpenAI", openAIUsersURL+"?limit=1", credentials["adminApiKey"], "application/json")
}

func testSlackConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "userToken"); err != nil {
		return err
	}
	var users []slackUser
	_, err := slackGet(ctx, credentials["userToken"], "https://slack.com/api/users.list?limit=1", &users)
	return err
}

func testTailscaleConnection(ctx context.Context, credentials map[string]string) error {
	// The users endpoint is unpaginated. A successful OAuth exchange for the
	// explicit users:read scope is the only bounded non-scan capability probe.
	_, err := tailscaleAccessToken(ctx, credentials)
	return err
}

func testTwingateConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "network", "apiToken"); err != nil {
		return err
	}
	network := strings.ToLower(credentials["network"])
	if !twingateNetworkPattern.MatchString(network) {
		return errors.New("Twingate network must be a network subdomain")
	}
	body, _ := json.Marshal(map[string]any{"query": `query BeaconConnectionTest { users(first: 1) { edges { node { id } } } }`})
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+network+".twingate.com/api/graphql/", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-KEY", credentials["apiToken"])
	return graphqlProbe(ctx, "Twingate", request, "users")
}

func testVercelConnection(ctx context.Context, credentials map[string]string) error {
	if err := require(credentials, "token", "teamId"); err != nil {
		return err
	}
	endpoint := vercelAPIBaseURL + "/v3/teams/" + url.PathEscape(credentials["teamId"]) + "/members?limit=1"
	return bearerProbe(ctx, "Vercel", endpoint, credentials["token"], "application/json")
}

func testZoomConnection(ctx context.Context, credentials map[string]string) error {
	token, err := zoomAccessToken(ctx, credentials)
	if err != nil {
		return err
	}
	return bearerProbe(ctx, "Zoom", zoomAPIBaseURL+"/users?page_size=1&status=active", token, "application/json")
}

func graphqlProbe(ctx context.Context, platform string, request *http.Request, field string) error {
	response, err := doVendorRequest(ctx, request)
	if err != nil {
		return ConnectionError{Code: VendorUnavailable}
	}
	defer response.Body.Close()
	if !successful(response.StatusCode) {
		return connectionHTTPError(response.StatusCode)
	}
	var payload struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []struct {
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if decodeVendorJSON(response.Body, 1<<20, &payload) != nil {
		return ConnectionError{Code: UnexpectedResponse}
	}
	if len(payload.Errors) > 0 {
		return vendorAPIError(platform, strings.ToLower(payload.Errors[0].Extensions.Code))
	}
	if len(payload.Data[field]) == 0 || string(payload.Data[field]) == "null" {
		return ConnectionError{Code: UnexpectedResponse}
	}
	return nil
}
