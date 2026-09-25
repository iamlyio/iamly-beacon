package collector

import (
	"errors"
	"sort"

	"github.com/iamlyio/iamly-beacon/internal/protocol"
)

const maxCloudKeys = 100_000
const maxCloudKeyRequests = 10_000

var errCloudKeyLimit = errors.New("cloud key inventory exceeded the safety limit")

// Counts are discovered resources, not an estimate of resources hidden by an
// incomplete listing. The coverage message makes that distinction explicit.
type cloudKeyInventory struct {
	keys       []protocol.KeyRecord
	seen       map[string]bool
	requests   int
	total      int
	scanned    int
	partial    bool
	discovered bool
}

func (inventory *cloudKeyInventory) request() error {
	if inventory.requests >= maxCloudKeyRequests {
		return errCloudKeyLimit
	}
	inventory.requests++
	return nil
}

func (inventory *cloudKeyInventory) add(key protocol.KeyRecord) error {
	if inventory.seen == nil {
		inventory.seen = make(map[string]bool)
	}
	if inventory.seen[key.ID] {
		return nil
	}
	if len(inventory.keys) >= maxCloudKeys {
		return errCloudKeyLimit
	}
	inventory.seen[key.ID] = true
	inventory.keys = append(inventory.keys, key)
	return nil
}

func (inventory *cloudKeyInventory) result(scope, details string) ([]protocol.KeyRecord, []protocol.KeyCoverage) {
	status := "complete"
	if inventory.partial {
		status = "partial"
		if !inventory.discovered && len(inventory.keys) == 0 {
			status = "unavailable"
		}
		details = "Some metadata could not be read (permissions, provider response, cancellation, or safety limit); totals count discovered resources only. " + details
	}
	if inventory.keys == nil {
		inventory.keys = []protocol.KeyRecord{}
	}
	sort.Slice(inventory.keys, func(i, j int) bool { return inventory.keys[i].ID < inventory.keys[j].ID })
	return inventory.keys, []protocol.KeyCoverage{{
		Kind: "encryption_key", Status: status, ResourcesScanned: inventory.scanned,
		ResourcesTotal: inventory.total, Message: stringPointer(scope + ". " + details),
	}}
}
