// Package directory is the AD inventory contract the later canonical projector
// will consume. This package does not write iga_identity_accounts.
package directory

import (
	"time"

	"github.com/google/uuid"
)

// Account kinds from §21.2. They are recorded on evidence now and projected
// into iga_identity_accounts only after the TRD2 M3 vocabulary lands.
const (
	KindADUser                  = "ad_user"
	KindADGroup                 = "ad_group"
	KindADComputer              = "ad_computer"
	KindADManagedServiceAccount = "ad_managed_service_account"
	BasisObserved               = "observed"
)

// ADInventorySnapshot is one completed (or partial) authoritative directory
// read. SourceKey is forest ID + canonical objectGUID; ObjectSID is secondary
// and is not part of the key, so a rename keeps the identity.
type ADInventorySnapshot struct {
	WorkspaceID  uuid.UUID
	ForestID     string
	DomainSID    string
	DomainDN     string
	InvocationID string
	ObservedAt   time.Time
	Objects      []ADObject
	Coverage     []ScopeCoverage
}

// ADObject is one sanitized directory object. Basis is observed.
type ADObject struct {
	AccountKind          string
	LDAPClass            string
	SourceKey            string
	ForestID             string
	ObjectGUID           string
	ObjectSID            string
	DistinguishedName    string
	SAMAccountName       string
	UserPrincipalName    string
	DisplayName          string
	MemberOf             []string
	Member               []string
	ServicePrincipalName []string
	Disabled             bool
	Basis                string
}

// ScopeCoverage is per-scope, per-class completeness. A scope is complete
// only when every requested class returned all of its pages.
type ScopeCoverage struct {
	BaseDN   string
	Class    string
	Complete bool
	Reason   string
	Seen     int
	ReadMode string
}
