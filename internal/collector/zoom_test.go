package collector

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
)

func TestZoomCollectsAndNormalizesEveryAccountStatus(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	requests := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		switch {
		case request.URL.Host == "zoom.us":
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("client:secret"))
			if request.Header.Get("Authorization") != want || request.URL.Query().Get("account_id") != "account" {
				t.Fatal("Zoom OAuth credentials were not encoded correctly")
			}
			return jsonResponse(http.StatusOK, `{"access_token":"local-access-token"}`), nil
		case request.URL.Path == "/v2/users":
			if request.Header.Get("Authorization") != "Bearer local-access-token" {
				t.Fatal("Zoom access token missing")
			}
			switch request.URL.Query().Get("status") {
			case "active":
				return jsonResponse(http.StatusOK, `{"users":[{"id":"1","email":"one@example.com","first_name":"Ada","last_name":"Lovelace","status":"active","role_name":"Owner","type":2,"created_at":"2024-01-02T03:04:05Z","last_login_time":"2026-08-12T10:00:00Z"}]}`), nil
			case "inactive":
				return jsonResponse(http.StatusOK, `{"users":[{"id":"2","email":"two@example.com","status":"inactive","type":1}]}`), nil
			case "pending":
				return jsonResponse(http.StatusOK, `{"users":[{"id":"3","email":"three@example.com","status":"pending","type":1}]}`), nil
			}
		}
		t.Fatalf("unexpected Zoom request %s", request.URL.String())
		return nil, nil
	})}

	members, spend, err := Zoom(context.Background(), map[string]string{
		"accountId": "account", "clientId": "client", "clientSecret": "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 3 || requests != 4 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Status != "active" || members[0].Name == nil || *members[0].Name != "Ada Lovelace" || members[0].Billable == nil || !*members[0].Billable {
		t.Fatalf("active member=%#v", members[0])
	}
	if members[1].Status != "deactivated" || members[1].Billable == nil || *members[1].Billable {
		t.Fatalf("inactive member=%#v", members[1])
	}
	if members[2].Status != "pending" {
		t.Fatalf("pending member=%#v", members[2])
	}
}

func TestZoomRejectsRepeatedPaginationCursor(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "zoom.us" {
			return jsonResponse(http.StatusOK, `{"access_token":"token"}`), nil
		}
		return jsonResponse(http.StatusOK, `{"users":[],"next_page_token":"same"}`), nil
	})}

	_, _, err := Zoom(context.Background(), map[string]string{
		"accountId": "account", "clientId": "client", "clientSecret": "secret",
	})
	if err != errRepeatedCursor {
		t.Fatalf("error=%v, want repeated cursor", err)
	}
}
