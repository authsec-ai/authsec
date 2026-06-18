package tokens

import "sync"

// Process-wide NativeKeyManager singleton. The native keyset is global (not
// per-request, not per-workspace), so a single instance is shared across all
// OAuthASController/Service constructions — mirroring the existing
// GetSpiffeKeyService() singleton pattern rather than threading the manager
// through every constructor.
var (
	defaultKeyMgr *NativeKeyManager
	keyMgrMu      sync.Mutex
)

// InitNativeKeys initializes the singleton with a Vault-backed key manager.
// Call once at startup (cmd/main.go) AFTER the Vault client is available so the
// keyset is persistent and shared across pods. Safe to call before NativeKeys().
//
// NOTE: until this is called with a real KVStore, NativeKeys() lazily creates an
// EPHEMERAL (per-process) keyset — fine for local dev and for Phase 0 where no
// native tokens are issued yet, but multi-pod issuance (Phase 2+) requires this
// to be wired to Vault so every pod verifies the same kids.
func InitNativeKeys(kv KVStore) *NativeKeyManager {
	keyMgrMu.Lock()
	defer keyMgrMu.Unlock()
	defaultKeyMgr = NewNativeKeyManager(kv)
	return defaultKeyMgr
}

// NativeKeys returns the singleton, lazily creating an ephemeral (nil-Vault)
// manager if InitNativeKeys was never called.
func NativeKeys() *NativeKeyManager {
	keyMgrMu.Lock()
	defer keyMgrMu.Unlock()
	if defaultKeyMgr == nil {
		defaultKeyMgr = NewNativeKeyManager(nil)
	}
	return defaultKeyMgr
}
