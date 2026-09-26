package adguid

import (
	"fmt"
	"strconv"
	"strings"
)

// userAccountControl bits the inventory records. LOCKOUT (0x10) and
// PASSWORD_EXPIRED (0x800000) are often set only on the computed attribute;
// callers may OR that value in before parsing. A string that merely contains
// the digit 2 is not a disabled account.
const (
	UACAccountDisable             uint32 = 0x00000002
	UACLockout                    uint32 = 0x00000010
	UACDontExpirePassword         uint32 = 0x00010000
	UACTrustedForDelegation       uint32 = 0x00080000 // unconstrained delegation
	UACNotDelegated               uint32 = 0x00100000 // sensitive and cannot be delegated
	UACPasswordExpired            uint32 = 0x00800000
	UACTrustedToAuthForDelegation uint32 = 0x01000000 // protocol transition
)

// Flags is the integer reading of userAccountControl.
type Flags struct {
	Raw                        uint32 `json:"raw"`
	AccountDisabled            bool   `json:"account_disabled"`
	LockedOut                  bool   `json:"locked_out"`
	PasswordExpired            bool   `json:"password_expired"`
	DontExpirePassword         bool   `json:"dont_expire_password"`
	TrustedForDelegation       bool   `json:"trusted_for_delegation"`
	NotDelegated               bool   `json:"not_delegated"`
	TrustedToAuthForDelegation bool   `json:"trusted_to_auth_for_delegation"`
	// Active is the legacy human-import bit: not disabled. Lockout and
	// expiry are recorded separately and do not flip this.
	Active bool `json:"active"`
}

// ParseUAC parses the decimal userAccountControl attribute. An empty value
// is "not disabled" (the attribute was absent). A non-integer is an error —
// it is never tested with strings.Contains.
func ParseUAC(s string) (Flags, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Flags{Active: true}, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return Flags{}, fmt.Errorf("userAccountControl %q is not an integer", s)
	}
	return FromUint(uint32(n)), nil
}

// FromUint tests the account-control bits.
func FromUint(v uint32) Flags {
	f := Flags{
		Raw:                        v,
		AccountDisabled:            v&UACAccountDisable != 0,
		LockedOut:                  v&UACLockout != 0,
		PasswordExpired:            v&UACPasswordExpired != 0,
		DontExpirePassword:         v&UACDontExpirePassword != 0,
		TrustedForDelegation:       v&UACTrustedForDelegation != 0,
		NotDelegated:               v&UACNotDelegated != 0,
		TrustedToAuthForDelegation: v&UACTrustedToAuthForDelegation != 0,
	}
	f.Active = !f.AccountDisabled
	return f
}
