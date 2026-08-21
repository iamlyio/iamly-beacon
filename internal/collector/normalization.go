package collector

import (
	"errors"
	"time"
)

const maxCollectedMembers = 100_000

var errMemberLimit = errors.New("vendor member count exceeded the safety limit")

func memberPageFits(current, incoming int) bool {
	return incoming >= 0 && current <= maxCollectedMembers && incoming <= maxCollectedMembers-current
}

func normalizedUnixSecondsPointer(value int64) *string {
	if value <= 0 {
		return nil
	}
	parsed := time.Unix(value, 0).UTC()
	if parsed.Year() < 1 || parsed.Year() > 9999 {
		return nil
	}
	return stringPointer(parsed.Format(time.RFC3339))
}

func normalizedRFC3339Pointer(value string) *string {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil
	}
	return stringPointer(parsed.UTC().Format(time.RFC3339Nano))
}

func normalizedDatePointer(value string) *string {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return nil
	}
	return stringPointer(parsed.UTC().Format(time.RFC3339))
}
