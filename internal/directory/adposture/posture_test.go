package adposture

import (
	"testing"

	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/authsec-ai/authsec/internal/directory/adldap"
)

const domain = "S-1-5-21-1-2-3"

func TestPrivilegedSIDIgnoresName(t *testing.T) {
	if !PrivilegedSID(domain, domain+"-512") {
		t.Fatal("domain RID 512 is privileged whatever its name is")
	}
	for _, rid := range []string{"518", "519", "520"} {
		if !PrivilegedSID(domain, domain+"-"+rid) {
			t.Fatalf("RID %s is privileged", rid)
		}
	}
	if PrivilegedSID(domain, domain+"-525") {
		t.Fatal("Protected Users (RID 525) is a hardening group, not a privilege")
	}
	for _, sid := range []string{
		SIDBuiltinAdministrators, SIDBuiltinAccountOperators, SIDBuiltinServerOperators,
		SIDBuiltinPrintOperators, SIDBuiltinBackupOperators,
	} {
		if !PrivilegedSID(domain, sid) {
			t.Fatalf("%s is privileged", sid)
		}
	}
	if PrivilegedSID(domain, domain+"-513") {
		t.Fatal("Domain Users is not a privileged RID")
	}
	if PrivilegedSID(domain, domain+"-1999") {
		t.Fatal("a look-alike RID is not privileged")
	}
	if PrivilegedSID("S-1-5-21-9-9-9", domain+"-512") {
		t.Fatal("RID 512 of another domain is not this domain's Domain Admins")
	}
	if PrivilegedSID("", domain+"-512") {
		t.Fatal("domain RIDs need a domain SID")
	}
	if !PrivilegedSID("", SIDBuiltinAdministrators) {
		t.Fatal("builtin SIDs do not need a domain SID")
	}
}

func TestProtectedUsersIsNotPrivileged(t *testing.T) {
	renamed := group("CN=Restricted Accounts,DC=authsec,DC=test", domain+"-525")
	look := group("CN=Protected Users,DC=authsec,DC=test", domain+"-1998")
	member := user("CN=pat,DC=authsec,DC=test", domain+"-1201", "pat")
	member.MemberOf = []string{renamed.DistinguishedName}
	decoy := user("CN=decoy,DC=authsec,DC=test", domain+"-1202", "decoy")
	decoy.MemberOf = []string{look.DistinguishedName}
	counted := user("CN=counted,DC=authsec,DC=test", domain+"-1203", "counted")
	counted.MemberOf = []string{renamed.DistinguishedName}
	counted.AdminCount = true
	primaryOnly := user("CN=primary,DC=authsec,DC=test", domain+"-1204", "primary")
	primaryOnly.PrimaryGroupID = 525

	got := index(Evaluate(domain, []adldap.Object{renamed, look, member, decoy, counted}, true))
	pat := got["pat"]
	if pat.Privileged == nil || *pat.Privileged || pat.Coverage != "complete" || !pat.ProtectedUsers {
		t.Fatalf("Protected Users member: %+v", pat)
	}
	if len(pat.PrivilegedPath) != 0 || pat.PrivilegedDirect || pat.PrivilegedNested {
		t.Fatalf("Protected Users must not produce a privileged path: %+v", pat)
	}
	if pat.AdminCountOrphan == nil || *pat.AdminCountOrphan {
		t.Fatalf("member without adminCount is not an orphan: %+v", pat)
	}
	if got["decoy"].ProtectedUsers || truth(got["decoy"].Privileged) || got["decoy"].Privileged == nil {
		t.Fatalf("look-alike Protected Users name: %+v", got["decoy"])
	}
	orphan := got["counted"]
	if orphan.Privileged == nil || *orphan.Privileged || !orphan.ProtectedUsers || !truth(orphan.AdminCountOrphan) {
		t.Fatalf("adminCount plus Protected Users is an orphan, not a privilege: %+v", orphan)
	}

	// The primary group is RID 525, and that group object was not read.
	// Membership is still evidence. The missing object keeps coverage partial,
	// so privileged stays unset.
	missing := index(Evaluate(domain, []adldap.Object{primaryOnly}, true))["primary"]
	if !missing.ProtectedUsers || missing.Coverage != "partial" || missing.Privileged != nil {
		t.Fatalf("primary Protected Users without the group object: %+v", missing)
	}
}

func TestRenamedDomainAdminsAndLookAlike(t *testing.T) {
	renamed := group("CN=Accounts Team,DC=authsec,DC=test", domain+"-512")
	look := group("CN=Domain Admins,DC=authsec,DC=test", domain+"-1999")
	member := user("CN=alice,DC=authsec,DC=test", domain+"-1101", "alice")
	member.MemberOf = []string{renamed.DistinguishedName}
	decoy := user("CN=bob,DC=authsec,DC=test", domain+"-1102", "bob")
	decoy.MemberOf = []string{look.DistinguishedName}

	got := index(Evaluate(domain, []adldap.Object{renamed, look, member, decoy}, true))
	if !truth(got["alice"].Privileged) || !got["alice"].PrivilegedDirect {
		t.Fatalf("renamed Domain Admins member: %+v", got["alice"])
	}
	if path := got["alice"].PrivilegedPath; len(path) != 1 || path[0] != renamed.ObjectSID {
		t.Fatalf("path = %v", path)
	}
	if truth(got["bob"].Privileged) || got["bob"].Privileged == nil {
		t.Fatalf("look-alike name must not be privileged: %+v", got["bob"])
	}
}

func TestNestedAndCyclicMembership(t *testing.T) {
	da := group("CN=Accounts Team,DC=authsec,DC=test", domain+"-512")
	mid := group("CN=nest,DC=authsec,DC=test", domain+"-2000")
	mid.MemberOf = []string{da.DistinguishedName}
	nested := user("CN=nested,DC=authsec,DC=test", domain+"-1103", "nested")
	nested.MemberOf = []string{mid.DistinguishedName}

	cycleA := group("CN=cycle-a,DC=authsec,DC=test", domain+"-3001")
	cycleB := group("CN=cycle-b,DC=authsec,DC=test", domain+"-3002")
	cycleA.MemberOf = []string{cycleB.DistinguishedName}
	cycleB.MemberOf = []string{cycleA.DistinguishedName}
	plain := user("CN=plain,DC=authsec,DC=test", domain+"-1104", "plain")
	plain.MemberOf = []string{cycleA.DistinguishedName}

	// Membership recorded only on the group, not on the user.
	viaMember := user("CN=via,DC=authsec,DC=test", domain+"-1105", "via")
	da.Member = []string{viaMember.DistinguishedName}

	got := index(Evaluate(domain, []adldap.Object{da, mid, nested, cycleA, cycleB, plain, viaMember}, true))
	if !truth(got["nested"].Privileged) || !got["nested"].PrivilegedNested || got["nested"].PrivilegedDirect {
		t.Fatalf("nested: %+v", got["nested"])
	}
	if len(got["nested"].PrivilegedPath) != 2 || got["nested"].PrivilegedPath[1] != da.ObjectSID {
		t.Fatalf("nested path = %v", got["nested"].PrivilegedPath)
	}
	if truth(got["plain"].Privileged) || got["plain"].DepthExceeded || got["plain"].Coverage != "complete" {
		t.Fatalf("cycle must finish and stay unprivileged: %+v", got["plain"])
	}
	if !truth(got["via"].Privileged) || !got["via"].PrivilegedDirect {
		t.Fatalf("member attribute must count: %+v", got["via"])
	}
}

func TestDepthExceededIsPartial(t *testing.T) {
	// g0 is a member of g1, and so on. The privileged group sits one hop
	// past the bound, so the walk must stop without calling the account
	// unprivileged.
	var objs []adldap.Object
	dns := make([]string, 0, MaxMembershipDepth+1)
	for i := 0; i < MaxMembershipDepth+1; i++ {
		g := group("CN=g"+itoa(uint32(i))+",DC=authsec,DC=test", domain+"-4"+itoa(uint32(i)))
		objs = append(objs, g)
		dns = append(dns, g.DistinguishedName)
	}
	for i := 0; i < len(dns)-1; i++ {
		objs[i].MemberOf = []string{dns[i+1]}
	}
	da := group("CN=Accounts Team,DC=authsec,DC=test", domain+"-512")
	objs[len(dns)-1].MemberOf = []string{da.DistinguishedName}
	objs = append(objs, da)
	u := user("CN=deep,DC=authsec,DC=test", domain+"-1106", "deep")
	u.MemberOf = []string{dns[0]}
	u.AdminCount = true
	objs = append(objs, u)

	got := index(Evaluate(domain, objs, true))["deep"]
	if got.Coverage != "partial" || !got.DepthExceeded {
		t.Fatalf("depth: %+v", got)
	}
	if got.Privileged != nil {
		t.Fatalf("past the bound must not assert privileged=%v", *got.Privileged)
	}
	if got.AdminCountOrphan != nil {
		t.Fatal("past the bound must not assert an orphan")
	}
}

func TestAdminCountOrphan(t *testing.T) {
	users := group("CN=Domain Users,DC=authsec,DC=test", domain+"-513")
	orphan := user("CN=orphan,DC=authsec,DC=test", domain+"-1107", "orphan")
	orphan.AdminCount = true
	orphan.PrimaryGroupID = 513
	still := user("CN=still,DC=authsec,DC=test", domain+"-1108", "still")
	still.AdminCount = true
	still.PrimaryGroupID = 512
	da := group("CN=Accounts Team,DC=authsec,DC=test", domain+"-512")

	got := index(Evaluate(domain, []adldap.Object{users, da, orphan, still}, true))
	if truth(got["orphan"].Privileged) || !truth(got["orphan"].AdminCountOrphan) {
		t.Fatalf("orphan: %+v", got["orphan"])
	}
	if !truth(got["still"].Privileged) || truth(got["still"].AdminCountOrphan) {
		t.Fatalf("adminCount with a path is not an orphan: %+v", got["still"])
	}
}

func TestPartialScopeNeverAssertsNotPrivileged(t *testing.T) {
	u := user("CN=alice,DC=authsec,DC=test", domain+"-1101", "alice")
	u.AdminCount = true
	u.PrimaryGroupID = 513
	got := index(Evaluate(domain, []adldap.Object{u}, false))["alice"]
	if got.Coverage != "partial" {
		t.Fatalf("coverage %s", got.Coverage)
	}
	if got.Privileged != nil || got.AdminCountOrphan != nil {
		t.Fatalf("partial asserted a negative: priv=%v orphan=%v", got.Privileged, got.AdminCountOrphan)
	}

	da := group("CN=Accounts Team,DC=authsec,DC=test", domain+"-512")
	u.MemberOf = []string{da.DistinguishedName}
	got = index(Evaluate(domain, []adldap.Object{da, u}, false))["alice"]
	if !truth(got.Privileged) || got.Coverage != "partial" {
		t.Fatalf("a seen path stays privileged on a partial scope: %+v", got)
	}
}

func TestDelegationAndManagedAccounts(t *testing.T) {
	u := user("CN=deleg,DC=authsec,DC=test", domain+"-1109", "deleg")
	u.AccountFlags = adguid.FromUint(512 | adguid.UACTrustedForDelegation | adguid.UACNotDelegated)
	u.AllowedToDelegateTo = []string{"HOST/db.authsec.test"}
	u.AccountFlags.TrustedToAuthForDelegation = true
	u.RBCDPrincipals = []string{domain + "-1110"}
	gmsa := user("CN=gmsa,DC=authsec,DC=test", domain+"-1111", "gmsa")
	gmsa.AccountKind = adldap.KindManagedServiceAccount
	gmsa.LDAPClass = adldap.ClassGMSA
	gmsa.ObjectClass = []string{adldap.ClassGMSA}
	smsa := user("CN=smsa,DC=authsec,DC=test", domain+"-1112", "smsa")
	smsa.AccountKind = adldap.KindManagedServiceAccount
	smsa.LDAPClass = adldap.ClassSMSA
	broken := user("CN=broken,DC=authsec,DC=test", domain+"-1113", "broken")
	broken.RBCDUnparsed = true

	got := index(Evaluate(domain, []adldap.Object{u, gmsa, smsa, broken}, true))
	if !got["deleg"].UnconstrainedDelegation || !got["deleg"].ConstrainedDelegation || !got["deleg"].ProtocolTransition {
		t.Fatalf("delegation flags: %+v", got["deleg"])
	}
	if !got["deleg"].SensitiveNotDelegated || len(got["deleg"].DelegationTargets) != 1 || len(got["deleg"].RBCDPrincipals) != 1 {
		t.Fatalf("targets: %+v", got["deleg"])
	}
	if !got["gmsa"].GMSA || got["gmsa"].SMSA || !got["smsa"].SMSA || got["smsa"].GMSA {
		t.Fatalf("msa gmsa=%+v smsa=%+v", got["gmsa"], got["smsa"])
	}
	if got["broken"].RBCDAsserted || got["broken"].Coverage != "partial" {
		t.Fatalf("unparsed RBCD: %+v", got["broken"])
	}
}

func TestPrimaryGroupUnresolvedIsPartial(t *testing.T) {
	u := user("CN=alice,DC=authsec,DC=test", domain+"-1101", "alice")
	u.PrimaryGroupID = 513
	got := index(Evaluate(domain, []adldap.Object{u}, true))["alice"]
	if got.Coverage != "partial" || got.Privileged != nil {
		t.Fatalf("missing primary group: %+v", got)
	}
}

func index(in []Result) map[string]Result {
	out := map[string]Result{}
	for _, r := range in {
		out[r.SAMAccountName] = r
	}
	return out
}

func truth(v *bool) bool { return v != nil && *v }

func user(dn, sid, sam string) adldap.Object {
	return adldap.Object{
		AccountKind: adldap.KindUser, LDAPClass: adldap.ClassUser, ObjectGUID: sam + "-guid",
		ObjectSID: sid, DistinguishedName: dn, SAMAccountName: sam,
		ObjectClass: []string{"user"}, AccountFlags: adguid.FromUint(512),
	}
}

func group(dn, sid string) adldap.Object {
	return adldap.Object{
		AccountKind: adldap.KindGroup, LDAPClass: adldap.ClassGroup, ObjectGUID: sid,
		ObjectSID: sid, DistinguishedName: dn, SAMAccountName: sid,
		ObjectClass: []string{"group"},
	}
}
