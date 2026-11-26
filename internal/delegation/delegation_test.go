package delegation

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDelegated(t *testing.T) {
	claims := map[string]interface{}{
		"permissions":  []interface{}{"a:b"},
		"agent_type":   "mcp-agent",
		"client_id":    "c1",
		"workspace_id": "w1",
	}
	ws, client, ok := Delegated(claims)
	if !ok || ws != "w1" || client != "c1" {
		t.Fatalf("Delegated = %q %q %v", ws, client, ok)
	}
	// A workload SVID without delegation claims is not a delegation token.
	if _, _, ok := Delegated(map[string]interface{}{"permissions": []interface{}{"a:b"}, "client_id": "c1"}); ok {
		t.Fatal("an SVID without agent_type was treated as delegated")
	}
}

func TestCheckLifetime(t *testing.T) {
	now := time.Now().Unix()
	ok := map[string]interface{}{"iat": float64(now), "exp": float64(now + 3600)}
	if err := CheckLifetime(ok); err != nil {
		t.Fatalf("1h token: %v", err)
	}
	long := map[string]interface{}{"iat": float64(now), "exp": float64(now + int64((MaxTTL + time.Hour).Seconds()))}
	if err := CheckLifetime(long); !errors.Is(err, ErrLifetime) {
		t.Fatalf("25h token: %v", err)
	}
	if err := CheckLifetime(map[string]interface{}{"iat": float64(now)}); !errors.Is(err, ErrLifetime) {
		t.Fatalf("token without exp: %v", err)
	}
}

func TestCapTTL(t *testing.T) {
	if got := CapTTL(48 * time.Hour); got != MaxTTL {
		t.Fatalf("CapTTL(48h) = %v", got)
	}
	if got := CapTTL(0); got != MaxTTL {
		t.Fatalf("CapTTL(0) = %v", got)
	}
	if got := CapTTL(time.Hour); got != time.Hour {
		t.Fatalf("CapTTL(1h) = %v", got)
	}
}

func TestCheckActiveFailsClosed(t *testing.T) {
	if err := CheckActive(context.Background(), nil, "w", "c", "t"); err == nil {
		t.Fatal("no database must not be treated as active")
	}
	claims := map[string]interface{}{
		"permissions": []interface{}{"a:b"}, "agent_type": "x",
		"iat": float64(time.Now().Unix()), "exp": float64(time.Now().Add(time.Hour).Unix()),
	}
	if err := Verify(context.Background(), nil, claims, "t"); err == nil {
		t.Fatal("a delegated token without client/workspace must not verify")
	}
}
