package services

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/authsec-ai/authsec/internal/directory/adldap"
	"github.com/authsec-ai/authsec/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestInventoryPostureFlagsPartialAndList(t *testing.T) {
	db := openInventoryDB(t)
	ws := uuid.New()
	cfgID := uuid.New()
	password, err := utils.Encrypt("CANARY-SECRET-DO-NOT-LEAK-8")
	require.NoError(t, err)
	require.NoError(t, db.Exec(`INSERT INTO sync_configurations
		(id, workspace_id, sync_type, is_active, ad_server, ad_username, ad_password, ad_use_ssl, ad_page_size, ad_change_tracking, ad_tracking_mode)
		VALUES (?, ?, 'active_directory', 1, 'dc.authsec.test:389', 'svc', ?, 0, 100, 0, 'usn')`,
		cfgID.String(), ws.String(), password).Error)

	const domain = "S-1-5-21-1-2-3"
	da := groupObj("00000000-0000-0000-0000-0000000000a1", "CN=Accounts Team,DC=authsec,DC=test", domain+"-512")
	nest := groupObj("00000000-0000-0000-0000-0000000000a2", "CN=nest,DC=authsec,DC=test", domain+"-2000")
	nest.MemberOf = []string{da.DistinguishedName}
	look := groupObj("00000000-0000-0000-0000-0000000000a3", "CN=Domain Admins,DC=authsec,DC=test", domain+"-1999")
	users := groupObj("00000000-0000-0000-0000-0000000000a4", "CN=Domain Users,DC=authsec,DC=test", domain+"-513")

	direct := userObj("00000000-0000-0000-0000-000000000001", "CN=direct,DC=authsec,DC=test", "direct", domain+"-1101")
	direct.MemberOf = []string{da.DistinguishedName}
	nested := userObj("00000000-0000-0000-0000-000000000002", "CN=nested,DC=authsec,DC=test", "nested", domain+"-1102")
	nested.MemberOf = []string{nest.DistinguishedName}
	decoy := userObj("00000000-0000-0000-0000-000000000003", "CN=decoy,DC=authsec,DC=test", "decoy", domain+"-1103")
	decoy.MemberOf = []string{look.DistinguishedName}
	uncon := userObj("00000000-0000-0000-0000-000000000004", "CN=uncon,DC=authsec,DC=test", "uncon", domain+"-1104")
	uncon.AccountFlags = adguid.FromUint(512 | adguid.UACTrustedForDelegation)
	con := userObj("00000000-0000-0000-0000-000000000005", "CN=con,DC=authsec,DC=test", "con", domain+"-1105")
	con.AccountFlags = adguid.FromUint(512 | adguid.UACTrustedToAuthForDelegation)
	con.AllowedToDelegateTo = []string{"HOST/db.authsec.test"}
	orphan := userObj("00000000-0000-0000-0000-000000000006", "CN=orphan,DC=authsec,DC=test", "orphan", domain+"-1106")
	orphan.AdminCount = true
	orphan.PrimaryGroupID = 513
	sens := userObj("00000000-0000-0000-0000-000000000007", "CN=sens,DC=authsec,DC=test", "sens", domain+"-1107")
	sens.AccountFlags = adguid.FromUint(512 | adguid.UACNotDelegated)
	gmsa := userObj("00000000-0000-0000-0000-000000000008", "CN=gmsa,DC=authsec,DC=test", "gmsa", domain+"-1108")
	gmsa.AccountKind = adldap.KindManagedServiceAccount
	gmsa.LDAPClass = adldap.ClassGMSA
	gmsa.ObjectClass = []string{adldap.ClassGMSA}
	rbcd := userObj("00000000-0000-0000-0000-000000000009", "CN=rbcd,DC=authsec,DC=test", "rbcd", domain+"-1109")
	rbcd.RBCDPrincipals = []string{uncon.ObjectSID}
	disabled := userObj("00000000-0000-0000-0000-00000000000a", "CN=disabled,DC=authsec,DC=test", "disabled", domain+"-1110")
	disabled.AccountFlags = adguid.FromUint(514)

	accounts := []adldap.Object{direct, nested, decoy, uncon, con, orphan, sens, gmsa, rbcd, disabled}
	groups := []adldap.Object{da, nest, look, users}
	complete := true
	svc := &ADInventoryService{DB: db, Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }}
	svc.NewReader = func(adldap.Conn) (ADReader, error) {
		return &fakeReader{
			ident: adldap.Identity{ForestID: "DC=authsec,DC=test", DomainDN: "DC=authsec,DC=test", DomainSID: domain, InvocationID: "dc-a"},
			read: func(class string, _ int64) adldap.ClassRead {
				switch class {
				case adldap.ClassGroup:
					return adldap.ClassRead{Complete: complete, Objects: groups, Reason: map[bool]string{false: "size_limit"}[complete]}
				case adldap.ClassUser:
					return adldap.ClassRead{Complete: true, Objects: accounts}
				default:
					return adldap.ClassRead{Complete: true}
				}
			},
		}, nil
	}
	ctx := context.Background()
	_, err = svc.PutConfig(ctx, ws, InventoryConfig{
		ConfigID: cfgID, PageSize: 100,
		Scopes: []InventoryScope{{BaseDN: "DC=authsec,DC=test", ObjectClasses: []string{adldap.ClassUser, adldap.ClassGroup}}},
	})
	require.NoError(t, err)

	view, err := svc.Run(ctx, ws, cfgID, "tester")
	require.NoError(t, err)
	if view.Status != "succeeded" {
		t.Fatalf("complete run status %s: %s", view.Status, view.Error)
	}
	page, err := svc.ListPosture(ctx, ws, view.ID, "", 2, 0)
	require.NoError(t, err)
	if page.Limit != 2 || page.NextOffset == nil || *page.NextOffset != 2 || len(page.Posture) != 2 {
		t.Fatalf("first page: %+v", page)
	}
	var all []PostureView
	for off := 0; ; {
		p, err := svc.ListPosture(ctx, ws, view.ID, "", 2, off)
		require.NoError(t, err)
		all = append(all, p.Posture...)
		if p.NextOffset == nil {
			break
		}
		off = *p.NextOffset
	}
	bySAM := map[string]PostureView{}
	for _, row := range all {
		bySAM[row.SAMAccountName] = row
	}
	if len(bySAM) != len(accounts) {
		t.Fatalf("posture rows = %d, want %d", len(bySAM), len(accounts))
	}
	if !truth(bySAM["direct"].Privileged) || !bySAM["direct"].PrivilegedDirect {
		t.Fatalf("direct: %+v", bySAM["direct"])
	}
	if path := bySAM["direct"].PrivilegedPath; len(path) != 1 || path[0] != da.ObjectSID {
		t.Fatalf("direct path %v", path)
	}
	if !truth(bySAM["nested"].Privileged) || !bySAM["nested"].PrivilegedNested {
		t.Fatalf("nested: %+v", bySAM["nested"])
	}
	if path := bySAM["nested"].PrivilegedPath; len(path) != 2 || path[0] != nest.ObjectSID || path[1] != da.ObjectSID {
		t.Fatalf("nested path %v", path)
	}
	if truth(bySAM["decoy"].Privileged) || bySAM["decoy"].Privileged == nil || bySAM["decoy"].Coverage != "complete" {
		t.Fatalf("look-alike name must be asserted not privileged: %+v", bySAM["decoy"])
	}
	if !bySAM["uncon"].UnconstrainedDelegation {
		t.Fatal("unconstrained delegation was not recorded")
	}
	if !bySAM["con"].ConstrainedDelegation || !bySAM["con"].ProtocolTransition || len(bySAM["con"].DelegationTargets) != 1 {
		t.Fatalf("constrained: %+v", bySAM["con"])
	}
	if !bySAM["orphan"].AdminCount || !truth(bySAM["orphan"].AdminCountOrphan) || truth(bySAM["orphan"].Privileged) {
		t.Fatalf("orphan: %+v", bySAM["orphan"])
	}
	if !bySAM["sens"].SensitiveNotDelegated {
		t.Fatal("sensitive-and-not-delegated was not recorded")
	}
	if !bySAM["gmsa"].GMSA || bySAM["gmsa"].SMSA {
		t.Fatalf("gmsa: %+v", bySAM["gmsa"])
	}
	if !bySAM["rbcd"].RBCDAsserted || len(bySAM["rbcd"].RBCDPrincipals) != 1 || bySAM["rbcd"].RBCDPrincipals[0] != uncon.ObjectSID {
		t.Fatalf("rbcd: %+v", bySAM["rbcd"])
	}
	if !bySAM["disabled"].AccountDisabled {
		t.Fatal("disabled account was not recorded")
	}
	one, err := svc.ListPosture(ctx, ws, view.ID, nested.ObjectGUID, 50, 0)
	require.NoError(t, err)
	if len(one.Posture) != 1 || one.Posture[0].SAMAccountName != "nested" {
		t.Fatalf("object filter: %+v", one)
	}
	if _, err := svc.ListPosture(ctx, uuid.New(), view.ID, "", 50, 0); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("other workspace err = %v", err)
	}
	blob, _ := json.Marshal(all)
	for _, secret := range []string{"msDS-ManagedPassword", "unicodePwd", "userPassword", "CANARY-SECRET-DO-NOT-LEAK-8"} {
		if strings.Contains(strings.ToLower(string(blob)), strings.ToLower(secret)) {
			t.Fatalf("posture list leaked %s", secret)
		}
	}

	complete = false
	partial, err := svc.Run(ctx, ws, cfgID, "tester")
	require.NoError(t, err)
	if partial.Status != "partial" {
		t.Fatalf("partial run: %+v", partial)
	}
	again, err := svc.ListPosture(ctx, ws, partial.ID, "", 50, 0)
	require.NoError(t, err)
	bySAM = map[string]PostureView{}
	for _, row := range again.Posture {
		bySAM[row.SAMAccountName] = row
	}
	if bySAM["nested"].Coverage != "partial" || !truth(bySAM["nested"].Privileged) {
		t.Fatalf("partial read must keep an observed privileged path: %+v", bySAM["nested"])
	}
	if bySAM["decoy"].Privileged != nil || bySAM["decoy"].AdminCountOrphan != nil {
		t.Fatalf("partial read asserted a negative: %+v", bySAM["decoy"])
	}
	if bySAM["orphan"].AdminCountOrphan != nil || bySAM["orphan"].Privileged != nil {
		t.Fatalf("partial adminCount must not be called an orphan: %+v", bySAM["orphan"])
	}
}

func userObj(guid, dn, sam, sid string) adldap.Object {
	return adldap.Object{
		AccountKind: adldap.KindUser, LDAPClass: adldap.ClassUser, Basis: adldap.BasisObserved,
		ObjectGUID: guid, DistinguishedName: dn, SAMAccountName: sam, ObjectSID: sid,
		ObjectClass: []string{"user"}, AccountFlags: adguid.FromUint(512),
	}
}

func groupObj(guid, dn, sid string) adldap.Object {
	return adldap.Object{
		AccountKind: adldap.KindGroup, LDAPClass: adldap.ClassGroup, Basis: adldap.BasisObserved,
		ObjectGUID: guid, DistinguishedName: dn, ObjectSID: sid, ObjectClass: []string{"group"},
	}
}

func truth(v *bool) bool { return v != nil && *v }
