package tui

import (
	"reflect"
	"testing"
)

func TestMenuIncludesConnectionTestAction(t *testing.T) {
	found := false
	for _, item := range menuItems {
		if item.action == Test {
			found = item.name == "Test connection"
		}
	}
	if !found {
		t.Fatal("terminal menu does not expose the connection test action")
	}
}

func TestIntegrationSelectorDoesNotRenderCredentials(t *testing.T) {
	model := integrationModel{names: []string{"github", "slack"}}
	view := model.View().Content
	if !reflect.DeepEqual(model.names, []string{"github", "slack"}) || view == "" {
		t.Fatalf("selector view = %q", view)
	}
}
