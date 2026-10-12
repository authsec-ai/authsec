package vault

// VaultClient interface defines the methods needed for vault operations
type VaultClient interface {
	WriteSecret(path string, data map[string]interface{}) error
	ReadSecret(path string) (map[string]interface{}, error)
	DeleteSecret(path string) error
}

// SecretDestroyer is a client that can remove a secret permanently: every
// version and its metadata (KV v2 DELETE <mount>/metadata/<path>), not only
// the latest version (DeleteSecret on a KV v2 data path is a soft delete:
// the version stays recoverable with "undelete"). Client implements it.
type SecretDestroyer interface {
	DestroySecret(path string) error
}

// Destroy removes the secret at path permanently when vc can (SecretDestroyer)
// and reports destroyed=false when vc only offers DeleteSecret, which it then
// calls (a soft delete on KV v2), so the caller can say so.
func Destroy(vc VaultClient, path string) (destroyed bool, err error) {
	if d, ok := vc.(SecretDestroyer); ok {
		return true, d.DestroySecret(path)
	}
	return false, vc.DeleteSecret(path)
}
