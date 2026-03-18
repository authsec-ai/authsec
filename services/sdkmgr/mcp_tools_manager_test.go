package sdkmgr

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
)

func TestGenerateUserToolSchemaFromMetadataPreservesEmptyRequiredArray(t *testing.T) {
	original := config.AppConfig
	config.AppConfig = &config.Config{SDKRequireSessionID: false}
	t.Cleanup(func() {
		config.AppConfig = original
	})

	manager := NewMCPToolsManager()
	schema := manager.GenerateUserToolSchemaFromMetadata(map[string]interface{}{
		"name":        "list_demo_notes",
		"description": "List the protected local demo notes",
		"inputSchema": map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
			"required":   []interface{}{},
		},
	})

	required, ok := schema.InputSchema["required"].([]string)
	if !ok {
		t.Fatalf("required type = %T, want []string", schema.InputSchema["required"])
	}
	if required == nil {
		t.Fatal("required should be an empty slice, got nil")
	}
	if len(required) != 0 {
		t.Fatalf("required = %v, want empty slice", required)
	}

	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	if strings.Contains(string(encoded), `"required":null`) {
		t.Fatalf("schema encoded required as null: %s", string(encoded))
	}
}

func TestGenerateUserToolSchemaFromMetadataSupportsStringSliceRequired(t *testing.T) {
	original := config.AppConfig
	config.AppConfig = &config.Config{SDKRequireSessionID: false}
	t.Cleanup(func() {
		config.AppConfig = original
	})

	manager := NewMCPToolsManager()
	schema := manager.GenerateUserToolSchemaFromMetadata(map[string]interface{}{
		"name":        "remember_note",
		"description": "Remember a note",
		"inputSchema": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"note": map[string]interface{}{"type": "string"},
			},
			"required": []string{"note"},
		},
	})

	required, ok := schema.InputSchema["required"].([]string)
	if !ok {
		t.Fatalf("required type = %T, want []string", schema.InputSchema["required"])
	}
	if len(required) != 1 || required[0] != "note" {
		t.Fatalf("required = %v, want [note]", required)
	}
}
