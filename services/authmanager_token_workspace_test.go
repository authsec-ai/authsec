package services

import (
	"errors"
	"testing"
	"time"

	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
	"github.com/google/uuid"
)

// AS-095: no session token is minted without a real workspace.
func TestTokensRequireAWorkspace(t *testing.T) {
	t.Setenv("JWT_DEF_SECRET", "def-secret-for-tests-0123456789abcdef")
	t.Setenv("JWT_SDK_SECRET", "sdk-secret-for-tests-0123456789abcdef")
	s, err := NewAuthManagerTokenService()
	if err != nil {
		t.Fatal(err)
	}
	user := uuid.New()
	nilWS := uuid.Nil

	if _, err := s.GenerateAdminToken(user, "a@x.test", nil, "", []string{"admin"}); !errors.Is(err, ErrNoWorkspace) {
		t.Errorf("admin token without workspace: err = %v, want ErrNoWorkspace", err)
	}
	if _, err := s.GenerateAdminToken(user, "a@x.test", &nilWS, "", nil); !errors.Is(err, ErrNoWorkspace) {
		t.Errorf("admin token for the nil workspace: err = %v, want ErrNoWorkspace", err)
	}
	for _, ws := range []string{"", "admin", uuid.Nil.String()} {
		if _, err := s.GenerateToken(TokenClaims{WorkspaceID: ws, UserID: &user, ExpiresIn: time.Minute}); !errors.Is(err, ErrNoWorkspace) {
			t.Errorf("GenerateToken(workspace %q): err = %v, want ErrNoWorkspace", ws, err)
		}
		if _, err := s.GenerateTokenViaAuthManager(&sharedmodels.TokenRequest{WorkspaceID: ws, EmailID: "a@x.test"}); !errors.Is(err, ErrNoWorkspace) {
			t.Errorf("GenerateTokenViaAuthManager(workspace %q): err = %v, want ErrNoWorkspace", ws, err)
		}
	}

	ws := uuid.New()
	if _, err := s.GenerateAdminToken(user, "a@x.test", &ws, "x.test", []string{"admin"}); err != nil {
		t.Errorf("admin token with a workspace: %v", err)
	}
}
