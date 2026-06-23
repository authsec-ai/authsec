//go:build integration || smoke

package tokens

// ResetForTest nullifies the NativeKeyManager singleton so each test binary
// boots with a fresh ephemeral keyset. Called once at the start of TestMain
// before any harness init.
func ResetForTest() {
	keyMgrMu.Lock()
	defer keyMgrMu.Unlock()
	defaultKeyMgr = nil
}
