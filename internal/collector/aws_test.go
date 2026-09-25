package collector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const awsTestKeyOne = "1234abcd-12ab-34cd-56ef-1234567890ab"
const awsTestKeyTwo = "2234abcd-12ab-34cd-56ef-1234567890ab"
const awsTestARNPrefix = "arn:aws:kms:us-east-1:123456789012:key/"

func awsTestCredentials() map[string]string {
	return map[string]string{"region": "us-east-1", "accessKeyId": "fixture-access-id", "secretAccessKey": "fixture-signing-secret", "sessionToken": "fixture-session-token"}
}

func awsFixtureTransport(t *testing.T, handler func(string, map[string]any) (int, string)) {
	t.Helper()
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Host != "kms.us-east-1.amazonaws.com" || request.URL.Path != "/" {
			t.Fatalf("unexpected AWS request %s %s", request.Method, request.URL)
		}
		authorization := request.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") || !strings.Contains(authorization, "/us-east-1/kms/aws4_request") || !strings.Contains(authorization, "Signature=") {
			t.Fatal("AWS request was not SigV4 signed for the configured KMS region")
		}
		var input map[string]any
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		status, body := handler(strings.TrimPrefix(request.Header.Get("X-Amz-Target"), "TrentService."), input)
		response := jsonResponse(status, body)
		response.Header = http.Header{"Content-Type": {"application/x-amz-json-1.1"}}
		return response, nil
	})}
}

func TestAWSKeysSignedMetadataPagination(t *testing.T) {
	aliasPages, keyPages, rotations := 0, 0, 0
	awsFixtureTransport(t, func(operation string, input map[string]any) (int, string) {
		switch operation {
		case "ListAliases":
			aliasPages++
			if aliasPages == 1 {
				return 200, `{"Aliases":[{"AliasName":"alias/aws/unassociated"}],"Truncated":true,"NextMarker":"aliases-2"}`
			}
			if input["Marker"] != "aliases-2" {
				t.Fatal("alias pagination cursor missing")
			}
			return 200, `{"Aliases":[{"AliasName":"alias/payments","TargetKeyId":"` + awsTestKeyOne + `"}],"Truncated":false}`
		case "ListKeys":
			keyPages++
			if keyPages == 1 {
				return 200, `{"Keys":[{"KeyId":"` + awsTestKeyOne + `","KeyArn":"` + awsTestARNPrefix + awsTestKeyOne + `"}],"Truncated":true,"NextMarker":"keys-2"}`
			}
			if input["Marker"] != "keys-2" {
				t.Fatal("key pagination cursor missing")
			}
			return 200, `{"Keys":[{"KeyId":"` + awsTestKeyTwo + `","KeyArn":"` + awsTestARNPrefix + awsTestKeyTwo + `"}],"Truncated":false}`
		case "DescribeKey":
			id, state, origin := awsTestKeyOne, "Enabled", "AWS_KMS"
			if input["KeyId"] == awsTestARNPrefix+awsTestKeyTwo {
				id, state, origin = awsTestKeyTwo, "PendingDeletion", "EXTERNAL"
			}
			return 200, `{"KeyMetadata":{"KeyId":"` + id + `","Arn":"` + awsTestARNPrefix + id + `","AWSAccountId":"123456789012","CreationDate":1704067200,"ValidTo":1735689600,"KeyState":"` + state + `","KeyUsage":"ENCRYPT_DECRYPT","KeySpec":"SYMMETRIC_DEFAULT","Origin":"` + origin + `","KeyManager":"CUSTOMER","SecretKey":"must-not-serialize"}}`
		case "GetKeyRotationStatus":
			rotations++
			return 200, `{"KeyRotationEnabled":true,"RotationPeriodInDays":90,"NextRotationDate":1735689600}`
		default:
			t.Fatalf("unexpected or unsafe operation %s", operation)
		}
		return 500, `{}`
	})
	keys, coverage := CollectKeys(context.Background(), "aws", awsTestCredentials())
	if len(keys) != 2 || len(coverage) != 1 || coverage[0].Status != "complete" || coverage[0].ResourcesScanned != 2 || coverage[0].ResourcesTotal != 2 || rotations != 1 || aliasPages != 2 || keyPages != 2 {
		t.Fatalf("keys=%#v coverage=%#v counts=%d,%d,%d", keys, coverage, rotations, aliasPages, keyPages)
	}
	if keys[0].Name != "alias/payments" || keys[0].Status != "active" || keys[1].Status != "pending_deletion" || keys[0].CreatedAt == nil || *keys[0].CreatedAt != "2024-01-01T00:00:00Z" {
		t.Fatalf("incorrect normalized keys %#v", keys)
	}
	if !strings.Contains(strings.Join(keys[0].Scopes, ","), "automatic-rotation:true") || !strings.Contains(strings.Join(keys[1].Scopes, ","), "automatic-rotation:not_applicable") {
		t.Fatal("rotation metadata is missing or inferred for an unsupported key")
	}
	for _, key := range keys {
		if key.Owner != nil || key.CreatedBy != nil || key.LastUsedAt != nil {
			t.Fatalf("unsupported attribution was invented: %#v", key)
		}
	}
	blob, err := json.Marshal(struct {
		Keys     []protocol.KeyRecord   `json:"keys"`
		Coverage []protocol.KeyCoverage `json:"keyCoverage"`
	}{keys, coverage})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"must-not-serialize", "fixture-access-id", "fixture-signing-secret", "fixture-session-token"} {
		if strings.Contains(string(blob), secret) {
			t.Fatal("serialized inventory contains secret material")
		}
	}
}

func TestAWSKeysPermissionCoveragePreservesMetadata(t *testing.T) {
	for _, denied := range []string{"ListKeys", "ListAliases", "DescribeKey", "GetKeyRotationStatus"} {
		t.Run(denied, func(t *testing.T) {
			awsFixtureTransport(t, func(operation string, input map[string]any) (int, string) {
				if operation == denied {
					return 400, `{"__type":"AccessDeniedException","message":"fixture-signing-secret"}`
				}
				switch operation {
				case "ListAliases":
					return 200, `{"Aliases":[]}`
				case "ListKeys":
					return 200, `{"Keys":[{"KeyId":"` + awsTestKeyOne + `","KeyArn":"` + awsTestARNPrefix + awsTestKeyOne + `"}]}`
				case "DescribeKey":
					return 200, `{"KeyMetadata":{"KeyId":"` + awsTestKeyOne + `","Arn":"` + awsTestARNPrefix + awsTestKeyOne + `","AWSAccountId":"123456789012","KeyState":"Enabled","KeySpec":"SYMMETRIC_DEFAULT","Origin":"AWS_KMS","CreationDate":1704067200}}`
				case "GetKeyRotationStatus":
					return 200, `{"KeyRotationEnabled":false}`
				default:
					t.Fatalf("unexpected operation %s", operation)
				}
				return 500, `{}`
			})
			keys, coverage := CollectKeys(context.Background(), "aws", awsTestCredentials())
			wantStatus := "partial"
			if denied == "ListKeys" {
				wantStatus = "unavailable"
			}
			if len(coverage) != 1 || coverage[0].Status != wantStatus || strings.Contains(*coverage[0].Message, "fixture-signing-secret") {
				t.Fatalf("coverage=%#v", coverage)
			}
			if denied != "ListKeys" && len(keys) != 1 {
				t.Fatal("successful key list metadata was discarded")
			}
			if denied == "DescribeKey" && keys[0].CreatedAt != nil {
				t.Fatal("creation time invented after denied description")
			}
			members, spend, err := AWS(context.Background(), awsTestCredentials())
			if err != nil || members == nil || len(members) != 0 || spend != nil {
				t.Fatal("AWS must remain an encryption-only snapshot")
			}
		})
	}
}

func TestAWSKeysRejectsCrossRegionAndRepeatedCursor(t *testing.T) {
	pages := 0
	awsFixtureTransport(t, func(operation string, input map[string]any) (int, string) {
		if operation == "ListAliases" {
			return 200, `{"Aliases":[]}`
		}
		if operation != "ListKeys" {
			t.Fatalf("followed a key outside configured scope: %s", operation)
		}
		pages++
		return 200, `{"Keys":[{"KeyId":"` + awsTestKeyOne + `","KeyArn":"arn:aws:kms:eu-west-1:123456789012:key/` + awsTestKeyOne + `"}],"Truncated":true,"NextMarker":"same"}`
	})
	keys, coverage := CollectKeys(context.Background(), "aws", awsTestCredentials())
	if len(keys) != 0 || coverage[0].Status != "partial" || pages != 2 {
		t.Fatalf("keys=%#v coverage=%#v pages=%d", keys, coverage, pages)
	}
}

func TestAWSConnectionUsesDefaultChainAndClassifiesPermissions(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "fixture-default-chain-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fixture-default-chain-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	awsFixtureTransport(t, func(operation string, input map[string]any) (int, string) {
		if operation != "ListKeys" || input["Limit"] != float64(1) {
			t.Fatal("connection probe exceeded its read scope")
		}
		return 400, `{"__type":"AccessDeniedException","message":"fixture-default-chain-secret"}`
	})
	err := TestConnection(context.Background(), "aws", map[string]string{"region": "us-east-1"})
	if ConnectionErrorCodeOf(err) != PermissionDenied {
		t.Fatalf("error=%v", err)
	}
}

func TestAWSInvalidConfigurationStopsBeforeNetwork(t *testing.T) {
	original := httpClient
	t.Cleanup(func() { httpClient = original })
	httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid credentials reached network")
		return nil, nil
	})}
	for _, credentials := range []map[string]string{{}, {"region": "https://attacker"}, {"region": "us-east-1", "accessKeyId": "incomplete"}, {"region": "us-east-1", "sessionToken": "orphan"}} {
		if ConnectionErrorCodeOf(TestConnection(context.Background(), "aws", credentials)) != InvalidConfiguration {
			t.Fatal("invalid AWS configuration accepted")
		}
	}
}

func TestAWSMetadataResponseIsBounded(t *testing.T) {
	body := &awsMetadataBody{ReadCloser: io.NopCloser(strings.NewReader("123456789")), remaining: 4}
	data, err := io.ReadAll(body)
	if err == nil || string(data) != "1234" {
		t.Fatalf("bounded body data=%q err=%v", data, err)
	}
}

func TestAWSKeysMissingMetadataDoesNotInferRotationApplicability(t *testing.T) {
	awsFixtureTransport(t, func(operation string, input map[string]any) (int, string) {
		switch operation {
		case "ListAliases":
			if limit, ok := input["Limit"].(float64); !ok || limit < 1 || limit > 100 {
				t.Fatal("ListAliases limit exceeds the provider's accepted range")
			}
			return 200, `{"Aliases":[]}`
		case "ListKeys":
			return 200, `{"Keys":[{"KeyId":"` + awsTestKeyOne + `","KeyArn":"` + awsTestARNPrefix + awsTestKeyOne + `"}]}`
		case "DescribeKey":
			return 200, `{"KeyMetadata":{"KeyId":"` + awsTestKeyOne + `","Arn":"` + awsTestARNPrefix + awsTestKeyOne + `","AWSAccountId":"123456789012"}}`
		default:
			t.Fatalf("requested rotation without required metadata: %s", operation)
		}
		return 500, `{}`
	})
	keys, coverage := CollectKeys(context.Background(), "aws", awsTestCredentials())
	if len(keys) != 1 || keys[0].Status != "unknown" || coverage[0].Status != "partial" ||
		strings.Join(keys[0].Scopes, ",") != "automatic-rotation:unknown" {
		t.Fatalf("missing metadata was inferred: keys=%#v coverage=%#v", keys, coverage)
	}
}

func TestAWSKeysRejectsCrossAccountDescription(t *testing.T) {
	awsFixtureTransport(t, func(operation string, input map[string]any) (int, string) {
		switch operation {
		case "ListAliases":
			return 200, `{"Aliases":[]}`
		case "ListKeys":
			return 200, `{"Keys":[{"KeyId":"` + awsTestKeyOne + `","KeyArn":"` + awsTestARNPrefix + awsTestKeyOne + `"}]}`
		case "DescribeKey":
			return 200, `{"KeyMetadata":{"KeyId":"` + awsTestKeyOne + `","Arn":"arn:aws:kms:us-east-1:999999999999:key/` + awsTestKeyOne + `","AWSAccountId":"999999999999","CreationDate":1704067200,"KeyState":"Enabled"}}`
		default:
			t.Fatalf("followed an out-of-account description: %s", operation)
		}
		return 500, `{}`
	})
	keys, coverage := CollectKeys(context.Background(), "aws", awsTestCredentials())
	if len(keys) != 1 || keys[0].Resource != awsTestARNPrefix+awsTestKeyOne ||
		keys[0].CreatedAt != nil || keys[0].Status != "unknown" || coverage[0].Status != "partial" {
		t.Fatalf("out-of-account metadata accepted: keys=%#v coverage=%#v", keys, coverage)
	}
}
