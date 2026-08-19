package collector

import (
	"context"
	"net/http"
	"testing"
)

func TestAsanaCollectsAllWorkspaceUsers(t *testing.T) {
	requests := 0
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodGet || request.Host != "app.asana.com" || request.URL.Path != "/api/1.0/users" {
			t.Fatalf("unexpected Asana request %s %s%s", request.Method, request.Host, request.URL.Path)
		}
		query := request.URL.Query()
		if request.Header.Get("Authorization") != "Bearer asana-secret" || query.Get("workspace") != "12345" ||
			query.Get("limit") != "100" || query.Get("opt_fields") != "gid,name,email" {
			t.Fatalf("invalid Asana request headers=%v query=%v", request.Header, query)
		}
		if requests == 1 {
			_, _ = response.Write([]byte(`{"data":[{"gid":"1","name":"Ada Lovelace","email":"ada@example.com"}],"next_page":{"offset":"next-offset"}}`))
			return
		}
		if query.Get("offset") != "next-offset" {
			t.Fatalf("offset=%q", query.Get("offset"))
		}
		_, _ = response.Write([]byte(`{"data":[{"gid":"2","name":"Grace Hopper","email":"grace@example.com"}],"next_page":null}`))
	}))

	members, spend, err := Asana(context.Background(), map[string]string{"token": "asana-secret", "workspaceGid": "12345"})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 2 || requests != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Status != "active" || members[0].Role == nil || *members[0].Role != "member" ||
		members[0].Email == nil || *members[0].Email != "ada@example.com" {
		t.Fatalf("member=%#v", members[0])
	}
}

func TestAsanaRejectsUnsafeWorkspaceGID(t *testing.T) {
	_, _, err := Asana(context.Background(), map[string]string{"token": "secret", "workspaceGid": "123/../../users"})
	if err == nil || err.Error() != "Asana workspace GID is invalid" {
		t.Fatalf("error=%v", err)
	}
}

func TestAsanaRejectsRepeatedPaginationOffset(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"data":[],"next_page":{"offset":"same"}}`))
	}))
	_, _, err := Asana(context.Background(), map[string]string{"token": "secret", "workspaceGid": "12345"})
	if err != errRepeatedCursor {
		t.Fatalf("error=%v, want repeated cursor", err)
	}
}

func TestAsanaRejectsMissingDataEnvelope(t *testing.T) {
	useVendorTestServer(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = response.Write([]byte(`{"next_page":null}`))
	}))
	_, _, err := Asana(context.Background(), map[string]string{"token": "secret", "workspaceGid": "12345"})
	if err == nil || err.Error() != "Asana users collection returned invalid JSON" {
		t.Fatalf("error=%v", err)
	}
}
