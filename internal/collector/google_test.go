package collector

import "testing"

func TestNormalizeGooglePrivateKeyAcceptsEscapedNewlines(t *testing.T) {
	got := normalizeGooglePrivateKey(`-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n`)
	want := "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
	if got != want {
		t.Fatalf("normalized key = %q, want %q", got, want)
	}
}

func TestNormalizeGooglePrivateKeyPreservesRealNewlines(t *testing.T) {
	want := "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
	if got := normalizeGooglePrivateKey(want); got != want {
		t.Fatalf("normalized key = %q, want %q", got, want)
	}
}
