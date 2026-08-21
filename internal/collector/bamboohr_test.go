package collector

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
)

const testBambooHRAPIKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestBambooHRCollectsCompleteEmployeeLifecycle(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	requests := 0
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.URL.Host != "acme.bamboohr.com" || request.URL.Path != "/api/v1/employees" {
			t.Fatalf("unexpected BambooHR endpoint %s", request.URL.String())
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(testBambooHRAPIKey+":x"))
		if request.Header.Get("Authorization") != wantAuth || request.Header.Get("Accept") != "application/json" {
			t.Fatal("BambooHR authentication headers are invalid")
		}
		if request.URL.Query().Get("fields") != "workEmail,hireDate,department" ||
			request.URL.Query().Get("page[limit]") != "2500" {
			t.Fatalf("unexpected BambooHR query %s", request.URL.RawQuery)
		}
		if requests == 1 {
			if request.URL.Query().Get("page[after]") != "" {
				t.Fatal("first page must not have a cursor")
			}
			return jsonResponse(http.StatusOK, `{"data":[{"employeeId":"101","firstName":"Ada","lastName":"Lovelace","workEmail":"ada@example.com","jobTitleName":"Engineer","department":"R&D","status":"active","hireDate":"2024-01-02"}],"meta":{"page":{"nextCursor":"next-page"}}}`), nil
		}
		if request.URL.Query().Get("page[after]") != "next-page" {
			t.Fatal("second page cursor is missing")
		}
		return jsonResponse(http.StatusOK, `{"data":[{"employeeId":"102","displayName":"Grace Hopper","workEmail":"grace@example.com","status":"inactive"}],"meta":{"page":{}}}`), nil
	})}

	members, spend, err := BambooHR(context.Background(), map[string]string{
		"companyDomain": "Acme", "apiKey": testBambooHRAPIKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if spend != nil || len(members) != 2 || requests != 2 {
		t.Fatalf("members=%#v spend=%#v requests=%d", members, spend, requests)
	}
	if members[0].Status != "active" || members[0].Role == nil || *members[0].Role != "Engineer · R&D" ||
		members[0].CreatedAt == nil || *members[0].CreatedAt != "2024-01-02T00:00:00Z" {
		t.Fatalf("active employee=%#v", members[0])
	}
	if members[1].Status != "deactivated" || members[1].Name == nil || *members[1].Name != "Grace Hopper" {
		t.Fatalf("inactive employee=%#v", members[1])
	}
}

func TestBambooHROmitsMalformedHireDate(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"data":[{"employeeId":"101","status":"active","hireDate":"0000-00-00"}],"meta":{"page":{}}}`), nil
	})}

	members, _, err := BambooHR(context.Background(), map[string]string{
		"companyDomain": "acme", "apiKey": testBambooHRAPIKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || members[0].CreatedAt != nil {
		t.Fatalf("members=%#v", members)
	}
}

func TestBambooHRRejectsUnsafeCompanyDomain(t *testing.T) {
	_, _, err := BambooHR(context.Background(), map[string]string{
		"companyDomain": "acme.example.com", "apiKey": testBambooHRAPIKey,
	})
	if err == nil {
		t.Fatal("expected an invalid company domain error")
	}
}

func TestBambooHRRejectsMalformedAPIKey(t *testing.T) {
	err := ValidateBambooHRCredentials(map[string]string{
		"companyDomain": "acme", "apiKey": "not-an-api-key",
	})
	if err == nil {
		t.Fatal("expected an invalid API key error")
	}
}

func TestBambooHRRejectsRestrictedWorkEmailCoverage(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"data":[{"employeeId":"101","status":"active","workEmail":null,"_restrictedFields":["workEmail"]}],"meta":{"page":{}}}`), nil
	})}

	_, _, err := BambooHR(context.Background(), map[string]string{
		"companyDomain": "acme", "apiKey": testBambooHRAPIKey,
	})
	if err == nil {
		t.Fatal("expected restricted work email coverage to fail")
	}
}

func TestBambooHRRejectsRepeatedPaginationCursor(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"data":[],"meta":{"page":{"nextCursor":"same"}}}`), nil
	})}

	_, _, err := BambooHR(context.Background(), map[string]string{
		"companyDomain": "acme", "apiKey": testBambooHRAPIKey,
	})
	if err != errRepeatedCursor {
		t.Fatalf("error=%v, want repeated cursor", err)
	}
}
