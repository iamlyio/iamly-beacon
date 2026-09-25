package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const miroFixtureMember = `{"id":"m1","email":"member@example.com","active":true,"role":"organization_internal_user","license":"full"}`

func miroFixtureServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	originalBase, originalClient := miroAPIBaseURL, httpClient
	server := httptest.NewServer(handler)
	miroAPIBaseURL, httpClient = server.URL+"/v2", server.Client()
	t.Cleanup(func() {
		miroAPIBaseURL, httpClient = originalBase, originalClient
		server.Close()
	})
}

func TestMiroCollectsOrganizationLifecycleRolesAndActivity(t *testing.T) {
	var cursors []string
	miroFixtureServer(t, func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v2/orgs/org-1/members" ||
			request.Header.Get("Authorization") != "Bearer local-test-token" || request.Header.Get("Accept") != "application/json" {
			t.Fatal("unexpected Miro member request")
		}
		query := request.URL.Query()
		if query.Get("limit") != "100" || query.Has("active") || query.Has("role") || query.Has("license") || query.Has("emails") {
			t.Fatalf("unexpected membership filters: %v", query)
		}
		cursor := query.Get("cursor")
		cursors = append(cursors, cursor)
		switch cursor {
		case "":
			_, _ = response.Write([]byte(`{"limit":100,"size":2,"cursor":"m2","data":[{"id":"m1","email":"admin@example.com","active":true,"role":"organization_internal_admin","license":"full","lastActivityAt":"2026-09-01T10:20:30+02:00","adminRoles":[{"type":"prebuilt","name":"User Admin"}]},{"id":"m2","email":"inactive@example.com","active":false,"role":"organization_internal_user","license":"free_restricted","lastActivityAt":"invalid"}]}`))
		case "m2":
			_, _ = response.Write([]byte(`{"limit":100,"size":2,"cursor":"","data":[{"id":"m3","email":"guest@example.com","active":true,"role":"organization_team_guest_user","license":"free","lastActivityAt":""},{"id":"m4","email":"external@example.com","active":true,"role":"organization_external_user","license":"occasional","adminRoles":[{"type":"custom","name":"Audit Admin"}]}]}`))
		default:
			t.Fatalf("unexpected cursor: %q", cursor)
		}
	})
	members, spend, err := Miro(context.Background(), map[string]string{"orgId": "org-1", "token": "local-test-token"})
	if err != nil || spend != nil || len(members) != 4 || !reflect.DeepEqual(cursors, []string{"", "m2"}) {
		t.Fatalf("collection: members=%v spend=%v cursors=%v error=%v", members, spend, cursors, err)
	}
	roles := []string{"admin · full · User Admin", "member · free_restricted", "guest · free", "external · occasional · Audit Admin"}
	for index, member := range members {
		if member.ID == nil || *member.ID != fmt.Sprintf("m%d", index+1) || member.Email == nil ||
			member.Role == nil || *member.Role != roles[index] || member.Name != nil || member.Username != nil || member.CreatedAt != nil || member.Billable != nil {
			t.Fatalf("member %d incorrectly normalized: %+v", index, member)
		}
		wantStatus := "active"
		if index == 1 {
			wantStatus = "deactivated"
		}
		if member.Status != wantStatus {
			t.Fatalf("member %d status=%q", index, member.Status)
		}
		if index == 0 {
			if member.LastLoginAt == nil || *member.LastLoginAt != "2026-09-01T08:20:30Z" {
				t.Fatalf("activity=%v", member.LastLoginAt)
			}
		} else if member.LastLoginAt != nil {
			t.Fatalf("unavailable activity was invented: %v", member.LastLoginAt)
		}
	}
}

func TestMiroPaginationCompletion(t *testing.T) {
	for _, test := range []struct {
		name         string
		count        int
		cursor       any
		wantRequests int
	}{
		{name: "full terminal page", count: 100, cursor: "", wantRequests: 1},
		{name: "full page then empty", count: 100, wantRequests: 2},
		{name: "short page without terminal cursor", count: 1, wantRequests: 2},
		{name: "empty organization", count: 0, wantRequests: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			miroFixtureServer(t, func(response http.ResponseWriter, request *http.Request) {
				requests++
				data := make([]map[string]any, 0, test.count)
				if requests == 1 {
					for index := range test.count {
						data = append(data, map[string]any{"id": fmt.Sprint(index + 1), "email": "member@example.com", "active": true, "role": "organization_internal_user", "license": "full"})
					}
				} else if requests != 2 || request.URL.Query().Get("cursor") != fmt.Sprint(test.count) {
					t.Fatal("pagination did not use last member ID")
				}
				payload := map[string]any{"data": data}
				if test.cursor != nil {
					payload["cursor"] = test.cursor
				}
				_ = json.NewEncoder(response).Encode(payload)
			})
			members, _, err := Miro(context.Background(), map[string]string{"orgId": "org", "token": "token"})
			if err != nil || len(members) != test.count || requests != test.wantRequests {
				t.Fatalf("members=%d requests=%d error=%v", len(members), requests, err)
			}
		})
	}
}

func TestMiroRejectsMalformedResponsesAndRedactsErrors(t *testing.T) {
	const secret = "never-output-this-token"
	for _, test := range []struct {
		name   string
		status int
		body   string
		code   ConnectionErrorCode
	}{
		{name: "missing data", body: `{}`, code: UnexpectedResponse},
		{name: "null data", body: `{"data":null}`, code: UnexpectedResponse},
		{name: "wrong data type", body: `{"data":{}}`, code: UnexpectedResponse},
		{name: "null response", body: `null`, code: UnexpectedResponse},
		{name: "error document", body: `{"message":"` + secret + `"}`, code: UnexpectedResponse},
		{name: "null member", body: `{"data":[null]}`, code: UnexpectedResponse},
		{name: "missing id", body: `{"data":[{"email":"member@example.com","active":true,"role":"member","license":"full"}]}`, code: UnexpectedResponse},
		{name: "missing email", body: `{"data":[{"id":"m1","active":true,"role":"member","license":"full"}]}`, code: UnexpectedResponse},
		{name: "missing active", body: `{"data":[{"id":"m1","email":"member@example.com","role":"member","license":"full"}]}`, code: UnexpectedResponse},
		{name: "wrong active type", body: `{"data":[{"id":"m1","email":"member@example.com","active":"true","role":"member","license":"full"}]}`, code: UnexpectedResponse},
		{name: "missing role", body: `{"data":[{"id":"m1","email":"member@example.com","active":true,"license":"full"}]}`, code: UnexpectedResponse},
		{name: "missing license", body: `{"data":[{"id":"m1","email":"member@example.com","active":true,"role":"member"}]}`, code: UnexpectedResponse},
		{name: "invalid admin roles", body: `{"data":[{"id":"m1","email":"member@example.com","active":true,"role":"member","license":"full","adminRoles":["admin"]}]}`, code: UnexpectedResponse},
		{name: "wrong cursor type", body: `{"data":[],"cursor":42}`, code: UnexpectedResponse},
		{name: "empty nonterminal page", body: `{"data":[],"cursor":"next"}`, code: UnexpectedResponse},
		{name: "inconsistent size", body: `{"data":[],"size":1}`, code: UnexpectedResponse},
		{name: "invalid limit", body: `{"data":[],"limit":0}`, code: UnexpectedResponse},
		{name: "unauthorized", status: http.StatusUnauthorized, body: secret, code: CredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, body: secret, code: PermissionDenied},
		{name: "invalid organization", status: http.StatusNotFound, body: secret, code: InvalidConfiguration},
	} {
		t.Run(test.name, func(t *testing.T) {
			miroFixtureServer(t, func(response http.ResponseWriter, _ *http.Request) {
				if test.status != 0 {
					response.WriteHeader(test.status)
				}
				_, _ = response.Write([]byte(test.body))
			})
			credentials := map[string]string{"orgId": "org", "token": secret}
			members, spend, err := Miro(context.Background(), credentials)
			if err == nil || members != nil || spend != nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("unsafe collection outcome: members=%v spend=%v error=%v", members, spend, err)
			}
			err = TestConnection(context.Background(), "miro", credentials)
			if err == nil || ConnectionErrorCodeOf(err) != test.code || strings.Contains(err.Error(), secret) {
				t.Fatalf("probe error=%v, want=%v", err, test.code)
			}
		})
	}
}

func TestMiroRejectsCursorCyclesAndBoundsPagination(t *testing.T) {
	for _, cycle := range []bool{true, false} {
		t.Run(fmt.Sprint("cycle=", cycle), func(t *testing.T) {
			requests := 0
			miroFixtureServer(t, func(response http.ResponseWriter, _ *http.Request) {
				requests++
				cursor := fmt.Sprint(requests)
				if cycle {
					cursor = fmt.Sprint(requests % 2)
				}
				_, _ = fmt.Fprintf(response, `{"data":[%s],"cursor":%q}`, miroFixtureMember, cursor)
			})
			members, _, err := Miro(context.Background(), map[string]string{"orgId": "org", "token": "token"})
			wantError, wantRequests := errPaginationLimit, maxVendorPages
			if cycle {
				wantError, wantRequests = errRepeatedCursor, 3
			}
			if !errors.Is(err, wantError) || members != nil || requests != wantRequests {
				t.Fatalf("error=%v requests=%d, want error=%v requests=%d", err, requests, wantError, wantRequests)
			}
		})
	}
}

func TestMiroRequiresCredentialsAndSanitizesTransportFailure(t *testing.T) {
	for _, credentials := range []map[string]string{{"orgId": "org"}, {"token": "token"}} {
		if _, _, err := Miro(context.Background(), credentials); err == nil {
			t.Fatal("accepted incomplete credentials")
		}
		if err := TestConnection(context.Background(), "miro", credentials); ConnectionErrorCodeOf(err) != InvalidConfiguration {
			t.Fatalf("missing credential probe=%v", err)
		}
	}
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("token-leak-sentinel")
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := Miro(ctx, map[string]string{"orgId": "org", "token": "token-leak-sentinel"})
	if err == nil || strings.Contains(err.Error(), "token-leak-sentinel") {
		t.Fatalf("unsafe transport error=%v", err)
	}
}

func TestMiroRejectsOversizedPagesAndResponses(t *testing.T) {
	for _, body := range []string{
		`{"data":[` + strings.TrimSuffix(strings.Repeat(miroFixtureMember+",", 101), ",") + `],"cursor":""}`,
		`{"data":[],"padding":"` + strings.Repeat("x", 1<<20) + `"}`,
	} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			miroFixtureServer(t, func(response http.ResponseWriter, _ *http.Request) {
				_, _ = response.Write([]byte(body))
			})
			members, _, err := Miro(context.Background(), map[string]string{"orgId": "org", "token": "token"})
			if err == nil || members != nil {
				t.Fatalf("accepted unbounded response: members=%d error=%v", len(members), err)
			}
		})
	}
}
