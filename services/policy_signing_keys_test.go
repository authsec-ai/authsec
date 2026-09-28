package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/sign"
)

func TestPolicyKeyCacheFollowsPath(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.pem")
	second := filepath.Join(dir, "b.pem")
	writeTestKey(t, first)
	writeTestKey(t, second)
	t.Setenv(EnvPolicySigningKeyPEM, first)
	t.Setenv(EnvPolicySigningKeyID, "current")
	t.Setenv(EnvPolicySigningOverlapUntil, "")
	now := time.Now()
	loaded, err := LoadPolicyKeys(now)
	if err != nil {
		t.Fatal(err)
	}
	firstPEM, err := sign.PublicPEM(loaded.Current.Public)
	if err != nil {
		t.Fatal(err)
	}
	writeTestKey(t, first)
	again, err := LoadPolicyKeys(now)
	if err != nil {
		t.Fatal(err)
	}
	againPEM, err := sign.PublicPEM(again.Current.Public)
	if err != nil {
		t.Fatal(err)
	}
	if againPEM != firstPEM {
		t.Fatal("same path reloaded the signing key inside the cache window")
	}
	t.Setenv(EnvPolicySigningKeyPEM, second)
	other, err := LoadPolicyKeys(now)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := sign.PublicPEM(other.Current.Public)
	if err != nil {
		t.Fatal(err)
	}
	if otherPEM == firstPEM {
		t.Fatal("a different PEM path reused the cached key")
	}
}

func writeTestKey(t *testing.T, path string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
