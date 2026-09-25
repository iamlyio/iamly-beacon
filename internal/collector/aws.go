package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscredentials "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
var awsAccountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var awsKeyIDPattern = regexp.MustCompile(`^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)

func ValidateAWSCredentials(credentials map[string]string) error {
	if len(credentials["region"]) > 64 || !awsRegionPattern.MatchString(credentials["region"]) {
		return ConnectionError{Code: InvalidConfiguration}
	}
	id, secret, session := credentials["accessKeyId"], credentials["secretAccessKey"], credentials["sessionToken"]
	if (id == "") != (secret == "") || (session != "" && id == "") {
		return ConnectionError{Code: InvalidConfiguration}
	}
	return nil
}

type awsMetadataHTTPClient struct{ client *http.Client }
type awsMetadataBody struct {
	io.ReadCloser
	remaining int64
}

func (body *awsMetadataBody) Read(p []byte) (int, error) {
	if body.remaining <= 0 {
		return 0, errors.New("AWS metadata response exceeded the safety limit")
	}
	if int64(len(p)) > body.remaining {
		p = p[:body.remaining]
	}
	n, err := body.ReadCloser.Read(p)
	body.remaining -= int64(n)
	return n, err
}

func (client awsMetadataHTTPClient) Do(request *http.Request) (*http.Response, error) {
	response, err := client.client.Do(request)
	if response != nil && response.Body != nil {
		response.Body = &awsMetadataBody{ReadCloser: response.Body, remaining: 8 << 20}
	}
	return response, err
}

func awsKMSClient(ctx context.Context, credentials map[string]string) (*kms.Client, error) {
	if err := ValidateAWSCredentials(credentials); err != nil {
		return nil, err
	}
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	options := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(credentials["region"]), awsconfig.WithHTTPClient(awsMetadataHTTPClient{client: &client}),
		awsconfig.WithRetryMaxAttempts(vendorRequestAttempts),
	}
	if credentials["accessKeyId"] != "" {
		options = append(options, awsconfig.WithCredentialsProvider(awscredentials.NewStaticCredentialsProvider(
			credentials["accessKeyId"], credentials["secretAccessKey"], credentials["sessionToken"],
		)))
	}
	configuration, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, ConnectionError{Code: InvalidConfiguration}
	}
	return kms.NewFromConfig(configuration), nil
}

func awsConnectionError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return normalizeConnectionError(ctx, ctx.Err())
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "AccessDeniedException":
			return ConnectionError{Code: PermissionDenied}
		case "UnrecognizedClientException", "InvalidClientTokenId", "ExpiredTokenException", "InvalidSignatureException", "SignatureDoesNotMatch":
			return ConnectionError{Code: CredentialsRejected}
		case "ThrottlingException", "LimitExceededException":
			return ConnectionError{Code: RateLimited}
		}
	}
	return ConnectionError{Code: VendorUnavailable}
}

func testAWSConnection(ctx context.Context, credentials map[string]string) error {
	client, err := awsKMSClient(ctx, credentials)
	if err != nil {
		return err
	}
	_, err = client.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(1)})
	return awsConnectionError(ctx, err)
}

// AWS is intentionally encryption-key-only, not a fabricated IAM directory.
// Key permission and transport failures belong to AWSKeys coverage, so a failed
// KMS read does not turn an otherwise valid snapshot into a collection failure.
func AWS(_ context.Context, credentials map[string]string) ([]protocol.Member, *protocol.Spend, error) {
	if err := ValidateAWSCredentials(credentials); err != nil {
		return nil, nil, err
	}
	return []protocol.Member{}, nil, nil
}

func awsMetadataTimestamp(value *time.Time) *string {
	if value == nil || value.Year() < 1 || value.Year() > 9999 {
		return nil
	}
	return stringPointer(value.UTC().Format(time.RFC3339Nano))
}

func awsKeyStatus(state types.KeyState) string {
	switch state {
	case types.KeyStateEnabled:
		return "active"
	case types.KeyStateDisabled:
		return "disabled"
	case types.KeyStatePendingDeletion, types.KeyStatePendingReplicaDeletion:
		return "pending_deletion"
	default:
		return "unknown"
	}
}

func awsKeyAccount(keyARN, keyID, region string) (string, bool) {
	parsed, err := arn.Parse(keyARN)
	if err != nil || len(keyARN) > 1000 || parsed.Service != "kms" || parsed.Region != region || !awsAccountPattern.MatchString(parsed.AccountID) ||
		!awsKeyIDPattern.MatchString(keyID) || parsed.Resource != "key/"+keyID {
		return "", false
	}
	return parsed.AccountID, true
}

func awsKeyAliases(ctx context.Context, client *kms.Client, inventory *cloudKeyInventory) (map[string][]string, error) {
	aliases := make(map[string][]string)
	seen := map[string]bool{}
	var marker *string
	count := 0
	for range maxVendorPages {
		if err := inventory.request(); err != nil {
			return aliases, err
		}
		page, err := client.ListAliases(ctx, &kms.ListAliasesInput{Limit: aws.Int32(100), Marker: marker})
		if err != nil {
			return aliases, err
		}
		for _, alias := range page.Aliases {
			id, name := aws.ToString(alias.TargetKeyId), aws.ToString(alias.AliasName)
			if id == "" {
				continue
			} // Predefined, unassociated AWS aliases are not keys.
			count++
			if count > maxCloudKeys {
				return aliases, errCloudKeyLimit
			}
			if !awsKeyIDPattern.MatchString(id) || !strings.HasPrefix(name, "alias/") || len(name) > 256 || len(aliases[id]) >= 80 {
				inventory.partial = true
				continue
			}
			aliases[id] = append(aliases[id], name)
		}
		if !page.Truncated {
			for id := range aliases {
				sort.Strings(aliases[id])
			}
			return aliases, nil
		}
		next := aws.ToString(page.NextMarker)
		if next == "" || len(next) > 1024 || seen[next] {
			return aliases, errRepeatedCursor
		}
		seen[next] = true
		marker = page.NextMarker
	}
	return aliases, errPaginationLimit
}

func awsKeyRotation(ctx context.Context, client *kms.Client, inventory *cloudKeyInventory, metadata *types.KeyMetadata) ([]string, error) {
	if metadata.KeySpec == "" || metadata.Origin == "" {
		return []string{"automatic-rotation:unknown"}, errors.New("AWS key rotation prerequisites are unavailable")
	}
	if metadata.KeySpec != types.KeySpecSymmetricDefault || metadata.Origin != types.OriginTypeAwsKms {
		return []string{"automatic-rotation:not_applicable"}, nil
	}
	if err := inventory.request(); err != nil {
		return []string{"automatic-rotation:unknown"}, err
	}
	rotation, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: metadata.Arn})
	if err != nil {
		return []string{"automatic-rotation:unknown"}, err
	}
	scopes := []string{fmt.Sprintf("automatic-rotation:%t", rotation.KeyRotationEnabled)}
	if rotation.RotationPeriodInDays != nil {
		scopes = append(scopes, fmt.Sprintf("rotation-period-days:%d", *rotation.RotationPeriodInDays))
	}
	if when := awsMetadataTimestamp(rotation.NextRotationDate); when != nil {
		scopes = append(scopes, "next-rotation:"+*when)
	}
	if when := awsMetadataTimestamp(rotation.OnDemandRotationStartDate); when != nil {
		scopes = append(scopes, "on-demand-rotation-start:"+*when)
	}
	return scopes, nil
}

// AWSKeys uses the SDK's SigV4-authenticated read APIs in one caller account and
// explicit region. No policies, grants, tags, cryptographic operations, or secret
// material are requested. Owner/creator/last-used are not native KMS metadata.
func AWSKeys(ctx context.Context, credentials map[string]string) ([]protocol.KeyRecord, []protocol.KeyCoverage) {
	inventory := &cloudKeyInventory{}
	region := credentials["region"]
	if len(region) > 64 || !awsRegionPattern.MatchString(region) {
		region = "invalid region"
	}
	account := "caller account"
	details := "Counts are discovered KMS keys, including AWS-managed keys. Aliases and rotation are metadata, not grants. Last use, owner, and creator are not exposed by KMS metadata and remain unknown; CloudTrail is not queried. Other accounts and regions are not scanned."
	finish := func() ([]protocol.KeyRecord, []protocol.KeyCoverage) {
		return inventory.result("AWS "+account+" / "+region, details)
	}
	client, err := awsKMSClient(ctx, credentials)
	if err != nil {
		inventory.partial = true
		return finish()
	}
	aliases, aliasErr := awsKeyAliases(ctx, client, inventory)
	if aliasErr != nil {
		inventory.partial = true
	}
	seenPages := map[string]bool{}
	seenKeys := map[string]bool{}
	var marker *string
	for range maxVendorPages {
		if err := inventory.request(); err != nil {
			inventory.partial = true
			return finish()
		}
		page, err := client.ListKeys(ctx, &kms.ListKeysInput{Limit: aws.Int32(1000), Marker: marker})
		if err != nil {
			inventory.partial = true
			return finish()
		}
		inventory.discovered = true
		for _, entry := range page.Keys {
			id, keyARN := aws.ToString(entry.KeyId), aws.ToString(entry.KeyArn)
			keyAccount, valid := awsKeyAccount(keyARN, id, region)
			if !valid || (account != "caller account" && account != keyAccount) {
				inventory.partial = true
				continue
			}
			account = keyAccount
			if seenKeys[id] {
				continue
			}
			if len(seenKeys) >= maxCloudKeys {
				inventory.partial = true
				return finish()
			}
			seenKeys[id] = true
			inventory.total++
			key := protocol.KeyRecord{ID: id, Kind: "encryption_key", Name: id, Resource: keyARN, Access: "unknown", Scopes: []string{}, Status: "unknown"}
			if len(aliases[id]) > 0 {
				key.Name = aliases[id][0]
			}
			for _, name := range aliases[id] {
				key.Scopes = append(key.Scopes, "alias:"+name)
			}
			if aliasErr != nil {
				key.Scopes = append(key.Scopes, "aliases:partial_or_unavailable")
			}
			if err := inventory.request(); err != nil {
				inventory.partial = true
				return finish()
			}
			described, describeErr := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: entry.KeyArn})
			complete := describeErr == nil && described.KeyMetadata != nil
			if complete {
				metadata := described.KeyMetadata
				if aws.ToString(metadata.Arn) != keyARN || aws.ToString(metadata.KeyId) != id || aws.ToString(metadata.AWSAccountId) != account {
					inventory.partial = true
					complete = false
				} else {
					key.Status = awsKeyStatus(metadata.KeyState)
					key.CreatedAt = awsMetadataTimestamp(metadata.CreationDate)
					key.ExpiresAt = awsMetadataTimestamp(metadata.ValidTo)
					key.Access = string(metadata.KeyUsage)
					if key.Access == "" {
						key.Access = "unknown"
					}
					if metadata.KeySpec != "" {
						key.Scopes = append(key.Scopes, "spec:"+string(metadata.KeySpec))
					}
					if metadata.Origin != "" {
						key.Scopes = append(key.Scopes, "origin:"+string(metadata.Origin))
					}
					if metadata.KeyManager != "" {
						key.Scopes = append(key.Scopes, "manager:"+string(metadata.KeyManager))
					}
					if when := awsMetadataTimestamp(metadata.DeletionDate); when != nil {
						key.Scopes = append(key.Scopes, "scheduled-deletion:"+*when)
					}
					rotation, rotationErr := awsKeyRotation(ctx, client, inventory, metadata)
					key.Scopes = append(key.Scopes, rotation...)
					if rotationErr != nil {
						inventory.partial = true
						complete = false
					}
				}
			}
			if !complete {
				inventory.partial = true
			}
			if complete && aliasErr == nil {
				inventory.scanned++
			}
			if err := inventory.add(key); err != nil {
				inventory.partial = true
				return finish()
			}
			if ctx.Err() != nil {
				inventory.partial = true
				return finish()
			}
		}
		if !page.Truncated {
			return finish()
		}
		next := aws.ToString(page.NextMarker)
		if next == "" || len(next) > 1024 || seenPages[next] {
			inventory.partial = true
			return finish()
		}
		seenPages[next] = true
		marker = page.NextMarker
	}
	inventory.partial = true
	return finish()
}
