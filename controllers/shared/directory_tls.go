package shared

import (
	"errors"
	"os"
	"strings"
)

// ErrADSkipVerifyRefused is returned for a directory-sync configuration that
// asks to skip LDAPS certificate verification where that is not allowed.
var ErrADSkipVerifyRefused = errors.New("skipping certificate verification is not allowed in production; " +
	"install the directory's CA or certificate on the server instead")

// CheckADSkipVerify refuses an AD configuration supplied by an admin (create,
// update, test, direct sync) that skips LDAPS certificate verification in
// production. DIRECTORY_SYNC_ALLOW_SKIP_VERIFY=true is the operator's explicit
// opt-out. Stored configurations are not re-checked on use, so a sync that
// already runs keeps running; it is logged instead.
func CheckADSkipVerify(useSSL, skipVerify bool) error {
	if !useSSL || !skipVerify {
		return nil
	}
	if !strings.EqualFold(os.Getenv("ENVIRONMENT"), "production") {
		return nil
	}
	if strings.EqualFold(os.Getenv("DIRECTORY_SYNC_ALLOW_SKIP_VERIFY"), "true") {
		return nil
	}
	return ErrADSkipVerifyRefused
}
