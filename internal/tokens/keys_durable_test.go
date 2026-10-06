package tokens

import (
	"context"
	"errors"
	"testing"
)

type fakeKV struct {
	data    map[string]map[string]interface{}
	readErr error
	writes  int
}

func (f *fakeKV) ReadKVSecret(_ context.Context, _, path string) (map[string]interface{}, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return f.data[path], nil
}

func (f *fakeKV) WriteKVSecret(_ context.Context, _, path string, data map[string]interface{}) error {
	f.writes++
	if f.data == nil {
		f.data = map[string]map[string]interface{}{}
	}
	f.data[path] = data
	return nil
}

func activeKID(m *NativeKeyManager) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.kid
}

// AS-036: a Vault read error is not "not found": the stored key must not be
// regenerated or overwritten, and the key already loaded keeps serving.
func TestNativeKeys_ReadErrorNeverOverwrites(t *testing.T) {
	t.Setenv(nativeKeyEnvB64, "")
	kv := &fakeKV{}
	m := NewNativeKeyManager(kv)
	if kv.writes != 2 || m.Ephemeral() {
		t.Fatalf("first start should create and persist both keys: writes=%d ephemeral=%v", kv.writes, m.Ephemeral())
	}
	kid := activeKID(m)
	stored := kv.data[nativeKeyPathActive]["private_key_pem"]

	kv.readErr = errors.New("vault: 503 sealed")
	m.Reload()
	if kv.writes != 2 {
		t.Fatalf("a read error wrote %d keys", kv.writes-2)
	}
	if kv.data[nativeKeyPathActive]["private_key_pem"] != stored {
		t.Fatal("stored key was overwritten")
	}
	if activeKID(m) != kid {
		t.Fatal("loaded key was replaced after a read error")
	}

	kv.readErr = nil
	m.Reload()
	if activeKID(m) != kid {
		t.Fatal("key changed after Vault recovered")
	}
}

// AS-036: unparseable stored material is an error, not a cue to regenerate.
func TestNativeKeys_UnparseableStoredKeyNotOverwritten(t *testing.T) {
	t.Setenv(nativeKeyEnvB64, "")
	kv := &fakeKV{data: map[string]map[string]interface{}{
		nativeKeyPathActive: {"private_key_pem": "garbage"},
	}}
	m := NewNativeKeyManager(kv)
	if kv.data[nativeKeyPathActive]["private_key_pem"] != "garbage" {
		t.Fatal("unparseable stored key was overwritten")
	}
	if !m.Ephemeral() {
		t.Fatal("without a usable stored key the active key must be reported ephemeral")
	}
}

// AS-036: production refuses ephemeral keys unless the key is pinned.
func TestNativeKeys_ProductionRequiresDurableKey(t *testing.T) {
	t.Setenv(nativeKeyEnvB64, "")
	m := NewNativeKeyManager(nil)
	if err := m.CheckDurable("production"); err == nil {
		t.Fatal("production accepted an ephemeral key")
	}
	if err := m.CheckDurable("development"); err != nil {
		t.Fatalf("development refused an ephemeral key: %v", err)
	}
	if err := NewNativeKeyManager(&fakeKV{}).CheckDurable("production"); err != nil {
		t.Fatalf("Vault-backed key refused: %v", err)
	}
}
