// Package adposture computes delegation and privileged-group evidence from
// one AD inventory read.
//
// Groups are identified by well-known RID or SID, never by display name.
// A renamed Domain Admins group is still privileged. A group that is only
// named "Domain Admins" is not.
//
// Coverage "partial" never stores privileged=false or admin_count_orphan=true.
// Those values assert that no privileged path exists. A partial scope, an
// unresolved group DN, a membership walk that hit the depth bound, or an
// unparsed delegation descriptor cannot support that assertion. A privileged
// path that was actually observed is still recorded as privileged=true.
//
// Protected Users (domain RID 525) is a hardening group. Membership restricts
// NTLM, delegation, and caching. It is recorded on ProtectedUsers and is not
// a privilege, so it never sets Privileged or clears an adminCount orphan.
//
// gMSA and sMSA are recorded from object class. msDS-GroupMSAMembership is
// not read: the posture allowlist does not include that descriptor, and the
// managed-password attribute is on the secret denylist.
//
// This package does not raise findings or alerts.
package adposture

import (
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/authsec-ai/authsec/internal/directory/adldap"
)

// MaxMembershipDepth is the number of group hops walked above an account.
// A longer chain is recorded as partial and is not treated as "not privileged".
const MaxMembershipDepth = 16

// Domain RIDs. The group's SID must be domainSID + "-" + RID.
const (
	RIDDomainAdmins             = 512
	RIDSchemaAdmins             = 518
	RIDEnterpriseAdmins         = 519
	RIDGroupPolicyCreatorOwners = 520
	RIDProtectedUsers           = 525
)

// Builtin privileged SIDs. These are absolute, not relative to the domain.
const (
	SIDBuiltinAdministrators   = "S-1-5-32-544"
	SIDBuiltinAccountOperators = "S-1-5-32-548"
	SIDBuiltinServerOperators  = "S-1-5-32-549"
	SIDBuiltinPrintOperators   = "S-1-5-32-550"
	SIDBuiltinBackupOperators  = "S-1-5-32-551"
)

// Result is the posture of one account in one run. Privileged and
// AdminCountOrphan are nil when the read cannot support a negative.
type Result struct {
	ObjectGUID              string
	ObjectSID               string
	AccountKind             string
	DistinguishedName       string
	SAMAccountName          string
	Coverage                string
	PartialReasons          []string
	UnconstrainedDelegation bool
	ConstrainedDelegation   bool
	ProtocolTransition      bool
	DelegationTargets       []string
	RBCDPrincipals          []string
	RBCDAsserted            bool
	Privileged              *bool
	PrivilegedDirect        bool
	PrivilegedNested        bool
	PrivilegedPath          []string
	AdminCount              bool
	AdminCountOrphan        *bool
	SensitiveNotDelegated   bool
	ProtectedUsers          bool
	GMSA                    bool
	SMSA                    bool
	DepthExceeded           bool
	AccountDisabled         bool
}

// PrivilegedSID reports whether sid is one of the well-known privileged
// groups. name is ignored: a look-alike CN is not privileged, and a renamed
// well-known group still is. An empty domain SID disables the domain RIDs
// and leaves the builtin SIDs in force.
//
// Domain RIDs are 512, 518, 519, and 520. Group Policy Creator Owners (520)
// is included because it can create and own GPOs; it is not an
// AdminSDHolder-protected group. Protected Users (525) is not privileged.
// Domain Controllers (516), read-only domain controllers (521), Key Admins
// (526), Enterprise Key Admins (527), and builtin Replicator (S-1-5-32-552)
// are not in this set: they identify a DC, a key-credential admin, or a
// legacy replication principal, not an admin of the domain.
// Schema Admins (518) and Enterprise Admins (519) match only when domainSID
// is the forest-root domain. A child-domain inventory does not see those
// forest-root groups.
func PrivilegedSID(domainSID, sid string) bool {
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return false
	}
	for _, builtin := range []string{
		SIDBuiltinAdministrators, SIDBuiltinAccountOperators, SIDBuiltinServerOperators,
		SIDBuiltinPrintOperators, SIDBuiltinBackupOperators,
	} {
		if strings.EqualFold(sid, builtin) {
			return true
		}
	}
	rid, ok := domainRID(domainSID, sid)
	if !ok {
		return false
	}
	switch rid {
	case "512", "518", "519", "520":
		return true
	default:
		return false
	}
}

// protectedUsersSID reports domain RID 525. The match is the SID, not the CN.
func protectedUsersSID(domainSID, sid string) bool {
	rid, ok := domainRID(domainSID, sid)
	return ok && rid == "525"
}

// domainRID returns the RID when sid is exactly domainSID plus one label.
func domainRID(domainSID, sid string) (string, bool) {
	sid = strings.TrimSpace(sid)
	domainSID = strings.TrimSpace(domainSID)
	if sid == "" || domainSID == "" || !strings.HasPrefix(strings.ToUpper(sid), strings.ToUpper(domainSID)+"-") {
		return "", false
	}
	rest := sid[len(domainSID):]
	if strings.Count(rest, "-") != 1 {
		return "", false
	}
	return sid[strings.LastIndex(sid, "-")+1:], true
}

// Evaluate walks every account in objects. scopeComplete is false when any
// class read in the run did not finish. Group objects are part of the walk
// and do not themselves get a result.
func Evaluate(domainSID string, objects []adldap.Object, scopeComplete bool) []Result {
	merged := mergeObjects(objects)
	byDN := map[string]adldap.Object{}
	bySID := map[string]adldap.Object{}
	for _, obj := range merged {
		if dn := normDN(obj.DistinguishedName); dn != "" {
			byDN[dn] = obj
		}
		if sid := strings.TrimSpace(obj.ObjectSID); sid != "" {
			bySID[strings.ToUpper(sid)] = obj
		}
	}
	parents := parentEdges(merged)

	var out []Result
	for _, obj := range merged {
		if !isAccount(obj) {
			continue
		}
		out = append(out, one(domainSID, obj, byDN, bySID, parents, scopeComplete))
	}
	return out
}

func one(domainSID string, obj adldap.Object, byDN map[string]adldap.Object, bySID map[string]adldap.Object, parents map[string][]string, scopeComplete bool) Result {
	r := Result{
		ObjectGUID:              obj.ObjectGUID,
		ObjectSID:               obj.ObjectSID,
		AccountKind:             obj.AccountKind,
		DistinguishedName:       obj.DistinguishedName,
		SAMAccountName:          obj.SAMAccountName,
		UnconstrainedDelegation: obj.AccountFlags.TrustedForDelegation,
		ConstrainedDelegation:   len(obj.AllowedToDelegateTo) > 0,
		ProtocolTransition:      obj.AccountFlags.TrustedToAuthForDelegation,
		DelegationTargets:       append([]string(nil), obj.AllowedToDelegateTo...),
		SensitiveNotDelegated:   obj.AccountFlags.NotDelegated,
		AdminCount:              obj.AdminCount,
		AccountDisabled:         obj.AccountFlags.AccountDisabled,
		GMSA:                    hasClass(obj, adldap.ClassGMSA),
		SMSA:                    hasClass(obj, adldap.ClassSMSA) && !hasClass(obj, adldap.ClassGMSA),
	}
	if obj.RBCDUnparsed {
		r.RBCDAsserted = false
	} else {
		r.RBCDAsserted = true
		r.RBCDPrincipals = append([]string(nil), obj.RBCDPrincipals...)
	}

	found, direct, nested, path, unresolved, depthExceeded, protected := walk(domainSID, obj, byDN, bySID, parents)
	r.PrivilegedDirect = direct
	r.PrivilegedNested = nested
	r.PrivilegedPath = path
	r.DepthExceeded = depthExceeded
	r.ProtectedUsers = protected

	var reasons []string
	if !scopeComplete {
		reasons = append(reasons, "scope_incomplete")
	}
	if unresolved {
		reasons = append(reasons, "unresolved_group")
	}
	if depthExceeded {
		reasons = append(reasons, "depth_exceeded")
	}
	if obj.RBCDUnparsed {
		reasons = append(reasons, "rbcd_unparsed")
	}
	partial := len(reasons) > 0
	if partial {
		r.Coverage = "partial"
		r.PartialReasons = reasons
	} else {
		r.Coverage = "complete"
	}

	switch {
	case found:
		r.Privileged = boolPtr(true)
		// A path was observed, so this account is not an adminCount orphan
		// even when the rest of the walk is partial.
		r.AdminCountOrphan = boolPtr(false)
	case partial:
		r.Privileged = nil
		r.AdminCountOrphan = nil
	default:
		r.Privileged = boolPtr(false)
		r.AdminCountOrphan = boolPtr(obj.AdminCount)
	}
	return r
}

type step struct {
	dn   string
	path []string
}

func walk(domainSID string, obj adldap.Object, byDN map[string]adldap.Object, bySID map[string]adldap.Object, parents map[string][]string) (found, direct, nested bool, path []string, unresolved, depthExceeded, protected bool) {
	var queue []step
	seenSeed := map[string]bool{}
	push := func(dn string) {
		dn = normDN(dn)
		if dn == "" || seenSeed[dn] {
			return
		}
		seenSeed[dn] = true
		queue = append(queue, step{dn: dn})
	}
	// memberOf on the account and member on the group are both edges.
	for _, dn := range parents[normDN(obj.DistinguishedName)] {
		push(dn)
	}
	if rid := obj.PrimaryGroupID; rid != 0 {
		sid, ok := primarySID(domainSID, rid)
		switch {
		case !ok:
			unresolved = true
		case PrivilegedSID(domainSID, sid):
			found = true
			direct = true
			path = []string{sid}
			if g, ok := bySID[strings.ToUpper(sid)]; ok {
				push(g.DistinguishedName)
			}
		case protectedUsersSID(domainSID, sid):
			// The primary group is Protected Users even when its object was
			// not read. A missing object still cannot be walked further.
			protected = true
			if g, ok := bySID[strings.ToUpper(sid)]; ok {
				push(g.DistinguishedName)
			} else {
				unresolved = true
			}
		default:
			if g, ok := bySID[strings.ToUpper(sid)]; ok {
				push(g.DistinguishedName)
			} else {
				unresolved = true
			}
		}
	}

	visited := map[string]bool{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur.dn] {
			continue
		}
		visited[cur.dn] = true
		g, ok := byDN[cur.dn]
		if !ok {
			unresolved = true
			continue
		}
		next := append(append([]string{}, cur.path...), strings.TrimSpace(g.ObjectSID))
		if protectedUsersSID(domainSID, g.ObjectSID) {
			protected = true
		}
		if PrivilegedSID(domainSID, g.ObjectSID) {
			found = true
			if len(next) <= 1 {
				direct = true
			} else {
				nested = true
			}
			if path == nil || len(next) < len(path) {
				path = next
			}
		}
		further := parents[cur.dn]
		if len(next) >= MaxMembershipDepth {
			if len(further) > 0 {
				depthExceeded = true
			}
			continue
		}
		for _, p := range further {
			if !visited[p] {
				queue = append(queue, step{dn: p, path: next})
			}
		}
	}
	return found, direct, nested, path, unresolved, depthExceeded, protected
}

func parentEdges(objects []adldap.Object) map[string][]string {
	seen := map[string]map[string]bool{}
	add := func(child, parent string) {
		child, parent = normDN(child), normDN(parent)
		if child == "" || parent == "" || child == parent {
			return
		}
		if seen[child] == nil {
			seen[child] = map[string]bool{}
		}
		seen[child][parent] = true
	}
	for _, obj := range objects {
		for _, parent := range obj.MemberOf {
			add(obj.DistinguishedName, parent)
		}
		for _, child := range obj.Member {
			add(child, obj.DistinguishedName)
		}
	}
	out := map[string][]string{}
	for child, parents := range seen {
		for parent := range parents {
			out[child] = append(out[child], parent)
		}
		sort.Strings(out[child])
	}
	return out
}

func mergeObjects(in []adldap.Object) []adldap.Object {
	order := make([]string, 0, len(in))
	byGUID := map[string]adldap.Object{}
	for _, obj := range in {
		guid := strings.ToLower(strings.TrimSpace(obj.ObjectGUID))
		if guid == "" {
			continue
		}
		prev, ok := byGUID[guid]
		if !ok {
			order = append(order, guid)
			byGUID[guid] = obj
			continue
		}
		byGUID[guid] = mergeObject(prev, obj)
	}
	out := make([]adldap.Object, 0, len(order))
	for _, guid := range order {
		out = append(out, byGUID[guid])
	}
	return out
}

func mergeObject(a, b adldap.Object) adldap.Object {
	if a.ObjectSID == "" {
		a.ObjectSID = b.ObjectSID
	}
	if a.DistinguishedName == "" {
		a.DistinguishedName = b.DistinguishedName
	}
	if a.AccountKind == "" {
		a.AccountKind = b.AccountKind
	}
	if a.LDAPClass == "" {
		a.LDAPClass = b.LDAPClass
	}
	if a.PrimaryGroupID == 0 {
		a.PrimaryGroupID = b.PrimaryGroupID
	}
	a.AdminCount = a.AdminCount || b.AdminCount
	a.RBCDUnparsed = a.RBCDUnparsed || b.RBCDUnparsed
	a.AccountFlags = mergeFlags(a.AccountFlags, b.AccountFlags)
	a.MemberOf = union(a.MemberOf, b.MemberOf)
	a.Member = union(a.Member, b.Member)
	a.AllowedToDelegateTo = union(a.AllowedToDelegateTo, b.AllowedToDelegateTo)
	a.RBCDPrincipals = union(a.RBCDPrincipals, b.RBCDPrincipals)
	a.ObjectClass = union(a.ObjectClass, b.ObjectClass)
	return a
}

func mergeFlags(a, b adguid.Flags) adguid.Flags {
	return adguid.FromUint(a.Raw | b.Raw)
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func isAccount(obj adldap.Object) bool {
	switch obj.AccountKind {
	case adldap.KindUser, adldap.KindComputer, adldap.KindManagedServiceAccount:
		return obj.ObjectGUID != ""
	default:
		return false
	}
}

func hasClass(obj adldap.Object, class string) bool {
	if strings.EqualFold(obj.LDAPClass, class) {
		return true
	}
	for _, c := range obj.ObjectClass {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}

func primarySID(domainSID string, rid uint32) (string, bool) {
	domainSID = strings.TrimSpace(domainSID)
	if domainSID == "" || rid == 0 {
		return "", false
	}
	return domainSID + "-" + itoa(rid), true
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func normDN(dn string) string {
	return strings.ToLower(strings.TrimSpace(dn))
}

func boolPtr(v bool) *bool { return &v }
