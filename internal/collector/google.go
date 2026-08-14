package collector

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const googleScope = "https://www.googleapis.com/auth/admin.directory.user.readonly"

func googleAccessToken(ctx context.Context, credentials map[string]string) (string, error) {
	if err := require(credentials, "clientEmail", "privateKey", "adminEmail"); err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(credentials["privateKey"]))
	if block == nil {
		return "", errors.New("Google private key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", errors.New("Google private key is not valid PKCS#8")
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("Google private key is not RSA")
	}
	now := time.Now().Unix()
	encode := func(value any) string {
		blob, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(blob)
	}
	unsigned := encode(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + encode(map[string]any{
		"iss": credentials["clientEmail"], "sub": credentials["adminEmail"],
		"scope": googleScope, "aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600,
	})
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("sign Google authorization assertion")
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion": {unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("Google token exchange failed: %w", err)
	}
	defer response.Body.Close()
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload) != nil || !successful(response.StatusCode) || payload.AccessToken == "" {
		return "", responseError("Google", response)
	}
	return payload.AccessToken, nil
}

func Google(ctx context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	token, err := googleAccessToken(ctx, credentials)
	if err != nil {
		return nil, nil, err
	}
	type directoryUser struct {
		ID               string `json:"id"`
		PrimaryEmail     string `json:"primaryEmail"`
		Suspended        bool   `json:"suspended"`
		Archived         bool   `json:"archived"`
		IsAdmin          bool   `json:"isAdmin"`
		IsDelegatedAdmin bool   `json:"isDelegatedAdmin"`
		CreationTime     string `json:"creationTime"`
		LastLoginTime    string `json:"lastLoginTime"`
		Name             struct {
			FullName string `json:"fullName"`
		} `json:"name"`
	}
	var members []protocol.Member
	cursor := ""
	seen := map[string]bool{}
	for {
		endpoint, _ := url.Parse("https://admin.googleapis.com/admin/directory/v1/users")
		query := endpoint.Query()
		query.Set("customer", "my_customer")
		query.Set("maxResults", "500")
		if cursor != "" {
			query.Set("pageToken", cursor)
		}
		endpoint.RawQuery = query.Encode()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := httpClient.Do(request)
		if err != nil {
			return nil, nil, fmt.Errorf("Google users.list failed: %w", err)
		}
		var payload struct {
			Users []directoryUser `json:"users"`
			Next  string          `json:"nextPageToken"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 32<<20)).Decode(&payload)
		response.Body.Close()
		if !successful(response.StatusCode) {
			return nil, nil, responseError("Google", response)
		}
		if decodeErr != nil {
			return nil, nil, errors.New("Google users.list returned invalid JSON")
		}
		for _, user := range payload.Users {
			status := "active"
			if user.Archived {
				status = "deactivated"
			} else if user.Suspended {
				status = "suspended"
			}
			role := "user"
			if user.IsAdmin {
				role = "super admin"
			} else if user.IsDelegatedAdmin {
				role = "delegated admin"
			}
			members = append(members, protocol.Member{ID: stringPointer(user.ID), Email: stringPointer(user.PrimaryEmail), Name: stringPointer(user.Name.FullName), Status: status, Role: stringPointer(role), CreatedAt: stringPointer(user.CreationTime), LastLoginAt: stringPointer(user.LastLoginTime)})
		}
		if payload.Next == "" {
			break
		}
		if seen[payload.Next] {
			return nil, nil, errRepeatedCursor
		}
		seen[payload.Next] = true
		cursor = payload.Next
	}
	return members, nil, nil
}
