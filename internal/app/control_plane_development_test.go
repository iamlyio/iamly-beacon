//go:build development

package app

import "testing"

func TestDevelopmentRuntimeUsesExplicitControlPlane(t *testing.T) {
	t.Setenv(developmentControlPlaneEnvironment, "  https://local-preview.trycloudflare.com  ")
	if controlPlaneURL := runtimeControlPlaneURL(); controlPlaneURL != "https://local-preview.trycloudflare.com" {
		t.Fatalf("development runtime selected %q", controlPlaneURL)
	}
}

func TestDevelopmentRuntimeDefaultsToCanonicalControlPlane(t *testing.T) {
	t.Setenv(developmentControlPlaneEnvironment, "")
	if controlPlaneURL := runtimeControlPlaneURL(); controlPlaneURL != canonicalControlPlane {
		t.Fatalf("development runtime selected %q", controlPlaneURL)
	}
}
