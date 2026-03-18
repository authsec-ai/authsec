package sdkmgr

import (
	"encoding/json"
	"testing"

	"github.com/authsec-ai/authsec/config"
	models "github.com/authsec-ai/authsec/models/sdkmgr"
	"gorm.io/datatypes"
)

func TestBuildMCPCallbackURL(t *testing.T) {
	t.Run("base URL without path", func(t *testing.T) {
		cfg := &config.Config{BaseURL: "http://localhost:7468"}
		got := buildMCPCallbackURL(cfg)
		want := "http://localhost:7468/authsec/sdkmgr/mcp-auth/callback"
		if got != want {
			t.Fatalf("buildMCPCallbackURL() = %q, want %q", got, want)
		}
	})

	t.Run("base URL with authsec path", func(t *testing.T) {
		cfg := &config.Config{BaseURL: "http://localhost:7468/authsec"}
		got := buildMCPCallbackURL(cfg)
		want := "http://localhost:7468/authsec/sdkmgr/mcp-auth/callback"
		if got != want {
			t.Fatalf("buildMCPCallbackURL() = %q, want %q", got, want)
		}
	})
}

func TestResolveRedirectURIUsesInspectorCallbackWhenReturnURLProvided(t *testing.T) {
	original := config.AppConfig
	config.AppConfig = &config.Config{
		BaseURL:          "http://localhost:7468",
		OAuthRedirectURI: "http://localhost:3000/oidc/auth/callback",
		ReactAppURL:      "http://localhost:3000",
	}
	t.Cleanup(func() {
		config.AppConfig = original
	})

	service := &MCPAuthService{}
	got := service.resolveRedirectURI("client-id", "http://localhost:6274/authorize")
	want := "http://localhost:7468/authsec/sdkmgr/mcp-auth/callback"
	if got != want {
		t.Fatalf("resolveRedirectURI() = %q, want %q", got, want)
	}
}

func TestExtractPendingReturnURL(t *testing.T) {
	raw, err := json.Marshal(map[string]interface{}{
		"return_url": "http://localhost:6274/authorize",
	})
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}

	session := &models.OAuthSession{
		UserInfo: datatypes.JSON(raw),
	}

	got := extractPendingReturnURL(session)
	want := "http://localhost:6274/authorize"
	if got != want {
		t.Fatalf("extractPendingReturnURL() = %q, want %q", got, want)
	}
}

func TestNormalizeReturnURLRejectsInvalidSchemes(t *testing.T) {
	if got := normalizeReturnURL("javascript:alert(1)"); got != "" {
		t.Fatalf("normalizeReturnURL() should reject invalid schemes, got %q", got)
	}
}
