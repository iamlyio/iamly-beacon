package protocol

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

type protocolContract struct {
	ContractVersion           string            `json:"contractVersion"`
	ProtocolVersion           int               `json:"protocolVersion"`
	Capabilities              []string          `json:"capabilities"`
	Platforms                 []string          `json:"platforms"`
	IntegrationTestErrorCodes []string          `json:"integrationTestErrorCodes"`
	Patterns                  map[string]string `json:"patterns"`
	Limits                    map[string]int    `json:"limits"`
}

func TestRuntimeMatchesVersionedProtocolContract(t *testing.T) {
	encoded, err := os.ReadFile("../../protocol/v1/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract protocolContract
	if err := json.Unmarshal(encoded, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.ContractVersion != "1.0.0" || contract.ProtocolVersion != ProtocolVersion {
		t.Fatalf("contract version = %q protocol = %d", contract.ContractVersion, contract.ProtocolVersion)
	}
	if !reflect.DeepEqual(contract.Capabilities, []string{IntegrationTestCapability}) {
		t.Fatalf("contract capabilities = %v", contract.Capabilities)
	}

	platforms := SupportedJobPlatformNames()
	sort.Strings(platforms)
	if !reflect.DeepEqual(contract.Platforms, platforms) {
		t.Fatalf("contract platforms = %v, runtime platforms = %v", contract.Platforms, platforms)
	}
	errorCodes := make([]string, 0, len(integrationTestErrorCodes))
	for code := range integrationTestErrorCodes {
		errorCodes = append(errorCodes, code)
	}
	sort.Strings(errorCodes)
	if !reflect.DeepEqual(contract.IntegrationTestErrorCodes, errorCodes) {
		t.Fatalf("contract error codes = %v, runtime error codes = %v", contract.IntegrationTestErrorCodes, errorCodes)
	}
	if contract.Patterns["beaconId"] != beaconIDPattern.String() ||
		contract.Patterns["jobId"] != jobIDPattern.String() ||
		contract.Patterns["testId"] != testIDPattern.String() ||
		contract.Patterns["leaseToken"] != leaseTokenPattern.String() {
		t.Fatal("contract identifier patterns differ from runtime validation")
	}
	if contract.Limits["reviewResultBytes"] != maxResultUploadBytes ||
		contract.Limits["integrationTestResultBytes"] != maxTestResultBytes ||
		contract.Limits["clientResponseBytes"] != maxResponseBytes {
		t.Fatalf("contract limits = %v", contract.Limits)
	}

	var schema any
	schemaBytes, err := os.ReadFile("../../protocol/v1/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("protocol schema is invalid JSON: %v", err)
	}
}
