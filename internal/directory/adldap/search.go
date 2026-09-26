package adldap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAP object classes the adapter will search. Anything else is rejected so a
// scope cannot inject a filter.
const (
	ClassUser     = "user"
	ClassGroup    = "group"
	ClassComputer = "computer"
	ClassSMSA     = "msDS-ManagedServiceAccount"
	ClassGMSA     = "msDS-GroupManagedServiceAccount"
)

// DefaultClasses is the administrator-approved set when a scope does not
// narrow it. Disabled accounts and accounts without mail are included.
func DefaultClasses() []string {
	return []string{ClassUser, ClassGroup, ClassComputer, ClassSMSA, ClassGMSA}
}

// Outcome is why a scope or class read stopped being complete.
type Outcome struct {
	Complete bool
	Reason   string // "", size_limit, referral, permission, paging_unsupported, error
}

// Searcher is the subset of *ldap.Conn the paged reader uses. Tests record the
// outgoing request instead of dialing a directory.
type Searcher interface {
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
}

// ClassFilter is the LDAP filter for one object class. usnFloor > 0 adds
// uSNChanged>=N for an incremental read. The class name is taken from a fixed
// map, never concatenated from the request.
func ClassFilter(class string, usnFloor int64) (string, error) {
	base, ok := classFilters[class]
	if !ok {
		return "", fmt.Errorf("object class %q is not in the inventory allowlist", class)
	}
	if usnFloor <= 0 {
		return base, nil
	}
	return fmt.Sprintf("(&%s(uSNChanged>=%d))", base, usnFloor), nil
}

// Users exclude computers and managed service accounts, which are also
// objectClass=user in AD. Disabled accounts are NOT excluded.
var classFilters = map[string]string{
	ClassUser:     "(&(objectClass=user)(!(objectClass=computer))(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))",
	ClassGroup:    "(objectClass=group)",
	ClassComputer: "(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))",
	ClassSMSA:     "(objectClass=msDS-ManagedServiceAccount)",
	ClassGMSA:     "(objectClass=msDS-GroupManagedServiceAccount)",
}

// PagedSearch reads every page of one search. The scope is complete only when
// every page returns and the paging cookie is empty. A size-limit, referral
// or permission error — or a server that drops the paging control — is partial.
// Entries already received are kept; the caller must not advance a cursor.
func PagedSearch(s Searcher, baseDN, filter string, pageSize uint32) ([]*ldap.Entry, Outcome) {
	if pageSize == 0 {
		pageSize = 500
	}
	attrs := InventoryAttributes()
	for _, a := range attrs {
		if Denied(a) {
			return nil, Outcome{Reason: "error"}
		}
	}
	paging := ldap.NewControlPaging(pageSize)
	var entries []*ldap.Entry
	for {
		req := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			filter,
			attrs,
			[]ldap.Control{paging},
		)
		sr, err := s.Search(req)
		if err != nil {
			return entries, Outcome{Complete: false, Reason: classify(err)}
		}
		if sr != nil {
			entries = append(entries, sr.Entries...)
		}
		if sr == nil {
			return entries, Outcome{Complete: false, Reason: "error"}
		}
		ctrl := ldap.FindControl(sr.Controls, ldap.ControlTypePaging)
		if ctrl == nil {
			return entries, Outcome{Complete: false, Reason: "paging_unsupported"}
		}
		next, ok := ctrl.(*ldap.ControlPaging)
		if !ok {
			return entries, Outcome{Complete: false, Reason: "paging_unsupported"}
		}
		if len(next.Cookie) == 0 {
			return entries, Outcome{Complete: true}
		}
		paging = next
	}
}

func classify(err error) string {
	var le *ldap.Error
	if errors.As(err, &le) {
		switch le.ResultCode {
		case ldap.LDAPResultSizeLimitExceeded, ldap.LDAPResultAdminLimitExceeded:
			return "size_limit"
		case ldap.LDAPResultReferral:
			return "referral"
		case ldap.LDAPResultInsufficientAccessRights:
			return "permission"
		}
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "size limit"):
		return "size_limit"
	case strings.Contains(msg, "referral"):
		return "referral"
	case strings.Contains(msg, "insufficient access"):
		return "permission"
	default:
		return "error"
	}
}

// Cursor is the persisted per-scope change-tracking position.
type Cursor struct {
	InvocationID string
	HighestUSN   int64
	// Mode is "usn". A stored "dirsync" cursor is not a uSNChanged position
	// and recovers with a full read. DirSync itself is rejected by the API.
	Mode string
}

// PlanRead decides a full scoped read or a uSNChanged incremental read.
// A DC change (invocationID) or a stored DirSync cursor forces a full read.
func PlanRead(tracking bool, stored Cursor, liveInvocation string) (mode string, usnFloor int64) {
	if !tracking {
		return "full", 0
	}
	if strings.EqualFold(stored.Mode, "dirsync") {
		return "full", 0
	}
	if stored.HighestUSN <= 0 || stored.InvocationID == "" || liveInvocation == "" {
		return "full", 0
	}
	if stored.InvocationID != liveInvocation {
		return "full", 0
	}
	return "incremental", stored.HighestUSN
}
