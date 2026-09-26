package services

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/authsec-ai/authsec/internal/directory/adldap"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestInventoryRunCursorRenamePartialAndSecrets(t *testing.T) {
	db := openInventoryDB(t)
	ws := uuid.New()
	cfgID := uuid.New()
	password, err := utils.Encrypt("CANARY-SECRET-DO-NOT-LEAK-1")
	require.NoError(t, err)
	require.NoError(t, db.Exec(`INSERT INTO sync_configurations
		(id, workspace_id, sync_type, is_active, ad_server, ad_username, ad_password, ad_use_ssl, ad_skip_verify, ad_page_size, ad_change_tracking, ad_start_tls, ad_tracking_mode)
		VALUES (?, ?, 'active_directory', 1, 'dc.authsec.test:636', 'svc-inventory', ?, 1, 0, 100, 1, 0, 'usn')`,
		cfgID.String(), ws.String(), password).Error)

	svc := &ADInventoryService{DB: db, Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }}
	ctx := context.Background()
	_, err = svc.PutConfig(ctx, ws, InventoryConfig{
		ConfigID: cfgID, ChangeTracking: true, PageSize: 100, UseSSL: true,
		Scopes: []InventoryScope{{BaseDN: "OU=Svc,DC=authsec,DC=test", ObjectClasses: []string{adldap.ClassUser, adldap.ClassGroup}}},
	})
	require.NoError(t, err)

	guidA := "03020100-0504-0706-0809-0a0b0c0d0e0f"
	guidB := "11111111-2222-3333-4444-555555555555"
	forest := "DC=authsec,DC=test"
	var floors []int64
	phase := 0
	invocation := "dc-a"
	svc.NewReader = func(c adldap.Conn) (ADReader, error) {
		if c.Password != "CANARY-SECRET-DO-NOT-LEAK-1" {
			t.Fatalf("bind password = %q", c.Password)
		}
		return &fakeReader{
			ident: adldap.Identity{ForestID: forest, DomainDN: forest, DomainSID: "S-1-5-21-1-2-3", InvocationID: invocation},
			read: func(class string, floor int64) adldap.ClassRead {
				floors = append(floors, floor)
				if class == adldap.ClassGroup {
					return adldap.ClassRead{Complete: true}
				}
				switch phase {
				case 0:
					return adldap.ClassRead{Complete: true, HighestUSN: 10, Objects: []adldap.Object{
						obj(adldap.ClassUser, guidA, "CN=alice,OU=Svc,DC=authsec,DC=test", "alice", false),
						obj(adldap.ClassUser, guidB, "CN=nomail,OU=Svc,DC=authsec,DC=test", "nomail", true),
					}}
				case 1, 2:
					// Rename alice. nomail is absent. Phase 1 is incremental and
					// must not tombstone; phase 2 is a full read after a DC change.
					return adldap.ClassRead{Complete: true, HighestUSN: 20, Objects: []adldap.Object{
						obj(adldap.ClassUser, guidA, "CN=alice-renamed,OU=Svc,DC=authsec,DC=test", "alice", false),
					}}
				default:
					return adldap.ClassRead{Complete: false, Reason: "size_limit", HighestUSN: 30, Objects: []adldap.Object{
						obj(adldap.ClassUser, guidA, "CN=alice-renamed,OU=Svc,DC=authsec,DC=test", "alice", false),
					}}
				}
			},
		}, nil
	}

	view, err := svc.Run(ctx, ws, cfgID, "tester")
	require.NoError(t, err)
	if view.Status != "succeeded" || view.ObjectsSeen != 2 {
		t.Fatalf("first run: %+v", view)
	}
	if view.Coverage[0].Complete == false && view.Coverage[1].Complete == false {
		t.Fatalf("expected a complete scope, coverage %+v", view.Coverage)
	}
	keyA, err := igagraph.ADIdentityKey(forest, guidA)
	require.NoError(t, err)
	keyB, err := igagraph.ADIdentityKey(forest, guidB)
	require.NoError(t, err)
	var n int64
	require.NoError(t, db.Model(&models.IGASourceObject{}).Where("recognition_key = ? AND lifecycle = ?", keyA, "active").Count(&n).Error)
	if n != 1 {
		t.Fatalf("alice rows = %d", n)
	}
	var nomail models.IGASourceObject
	require.NoError(t, db.Where("recognition_key = ?", keyB).First(&nomail).Error)
	if !strings.Contains(string(nomail.NormalizedPayload), `"account_disabled":true`) {
		t.Fatalf("disabled account was not recorded: %s", nomail.NormalizedPayload)
	}
	if strings.Contains(string(nomail.NormalizedPayload), `"mail":"`) {
		t.Fatalf("no-mail account stored an address: %s", nomail.NormalizedPayload)
	}

	phase = 1
	floors = nil
	view, err = svc.Run(ctx, ws, cfgID, "tester")
	require.NoError(t, err)
	if view.Status != "succeeded" {
		t.Fatalf("second run: %+v", view)
	}
	if len(floors) == 0 || floors[0] == 0 {
		t.Fatalf("incremental read did not use the cursor: %v", floors)
	}
	require.NoError(t, db.Model(&models.IGASourceObject{}).Where("recognition_key = ?", keyA).Count(&n).Error)
	if n != 1 {
		t.Fatalf("rename created a second identity, rows=%d", n)
	}
	var alice models.IGASourceObject
	require.NoError(t, db.Where("recognition_key = ?", keyA).First(&alice).Error)
	if !strings.Contains(string(alice.Locator), "alice-renamed") {
		t.Fatalf("locator did not follow the rename: %s", alice.Locator)
	}
	var gone models.IGASourceObject
	require.NoError(t, db.Where("recognition_key = ?", keyB).First(&gone).Error)
	if gone.Lifecycle != models.LifecycleActive {
		t.Fatalf("incremental read tombstoned an absent object: %s", gone.Lifecycle)
	}

	// A DC change invalidates the cursor. The recovery read is full, so the
	// account that is no longer in the scope can be tombstoned.
	invocation = "dc-b"
	phase = 2
	floors = nil
	view, err = svc.Run(ctx, ws, cfgID, "tester")
	require.NoError(t, err)
	if view.Status != "succeeded" || view.Mode != "full" {
		t.Fatalf("DC recovery: %+v", view)
	}
	if len(floors) == 0 || floors[0] != 0 {
		t.Fatalf("DC recovery used a cursor floor: %v", floors)
	}
	require.NoError(t, db.Where("recognition_key = ?", keyB).First(&gone).Error)
	if gone.Lifecycle != models.LifecycleTombstoned {
		t.Fatalf("absent object lifecycle = %s", gone.Lifecycle)
	}
	var obs int64
	require.NoError(t, db.Model(&models.IGAObservation{}).Where("mode = ?", models.EvidenceObserved).Count(&obs).Error)
	if obs < 2 {
		t.Fatalf("observed evidence rows = %d", obs)
	}

	phase = 3
	before := floors
	_ = before
	view, err = svc.Run(ctx, ws, cfgID, "tester")
	require.NoError(t, err)
	if view.Status != "partial" {
		t.Fatalf("size limit must be partial, got %+v", view)
	}
	var cur models.ADInventoryCursor
	require.NoError(t, db.Where("workspace_id = ?", ws.String()).First(&cur).Error)
	if cur.HighestUSN != 20 {
		t.Fatalf("partial read advanced the cursor to %d", cur.HighestUSN)
	}

	// A secret attribute planted in the stored payload must not survive a list.
	poisoned := append([]byte(nil), alice.NormalizedPayload...)
	var generic map[string]interface{}
	require.NoError(t, json.Unmarshal(poisoned, &generic))
	generic["msDS-ManagedPassword"] = "CANARY-SECRET-DO-NOT-LEAK-9"
	raw, _ := json.Marshal(generic)
	require.NoError(t, db.Model(&models.IGASourceObject{}).Where("id = ?", alice.ID).Update("normalized_payload", raw).Error)
	page, err := svc.ListObjects(ctx, ws, cfgID, 50, 0)
	require.NoError(t, err)
	blob, _ := json.Marshal(page)
	if strings.Contains(string(blob), "CANARY-SECRET-DO-NOT-LEAK-9") || strings.Contains(strings.ToLower(string(blob)), "msds-managedpassword") {
		t.Fatalf("list leaked a secret: %s", blob)
	}
	for _, o := range page.Objects {
		if o.ObjectGUID == guidB {
			t.Fatal("tombstoned object was listed")
		}
	}
}

func TestDirSyncRejectedAndDCChangeRecoversWithFullRead(t *testing.T) {
	db := openInventoryDB(t)
	ws, cfgID := uuid.New(), uuid.New()
	password, err := utils.Encrypt("CANARY-SECRET-DO-NOT-LEAK-2")
	require.NoError(t, err)
	require.NoError(t, db.Exec(`INSERT INTO sync_configurations
		(id, workspace_id, sync_type, is_active, ad_server, ad_username, ad_password, ad_use_ssl, ad_change_tracking, ad_tracking_mode, ad_page_size)
		VALUES (?, ?, 'active_directory', 1, 'dc.authsec.test:389', 'svc', ?, 0, 1, 'usn', 50)`,
		cfgID.String(), ws.String(), password).Error)
	svc := &ADInventoryService{DB: db}
	ctx := context.Background()
	_, err = svc.PutConfig(ctx, ws, InventoryConfig{
		ConfigID: cfgID, ChangeTracking: true, TrackingMode: "dirsync",
		Scopes: []InventoryScope{{BaseDN: "DC=authsec,DC=test"}},
	})
	if err == nil || err.Error() != models.DirSyncUnsupportedMessage {
		t.Fatalf("dirsync err = %v", err)
	}
	var cursors int64
	require.NoError(t, db.Model(&models.ADInventoryCursor{}).Count(&cursors).Error)
	if cursors != 0 {
		t.Fatalf("dirsync wrote %d cursor rows", cursors)
	}

	_, err = svc.PutConfig(ctx, ws, InventoryConfig{
		ConfigID: cfgID, ChangeTracking: true, TrackingMode: "usn",
		Scopes: []InventoryScope{{BaseDN: "DC=authsec,DC=test"}},
	})
	require.NoError(t, err)
	var floors []int64
	invocation := "dc-a"
	svc.NewReader = func(c adldap.Conn) (ADReader, error) {
		return &fakeReader{
			ident: adldap.Identity{ForestID: "DC=authsec,DC=test", InvocationID: invocation, DomainSID: "S-1-5-21-9"},
			read: func(class string, floor int64) adldap.ClassRead {
				floors = append(floors, floor)
				if class != adldap.ClassUser {
					return adldap.ClassRead{Complete: true}
				}
				return adldap.ClassRead{Complete: true, HighestUSN: 5, Objects: []adldap.Object{
					obj(adldap.ClassUser, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "CN=u,DC=authsec,DC=test", "u", false),
				}}
			},
		}, nil
	}
	if _, err := svc.Run(ctx, ws, cfgID, "tester"); err != nil {
		t.Fatal(err)
	}
	floors = nil
	invocation = "dc-b"
	if _, err := svc.Run(ctx, ws, cfgID, "tester"); err != nil {
		t.Fatal(err)
	}
	if len(floors) == 0 {
		t.Fatal("DC change produced no reads")
	}
	for _, f := range floors {
		if f != 0 {
			t.Fatalf("DC recovery used incremental floor %d (%v)", f, floors)
		}
	}
}

func TestProductionRefusesSkipVerify(t *testing.T) {
	db := openInventoryDB(t)
	ws, cfgID := uuid.New(), uuid.New()
	require.NoError(t, db.Exec(`INSERT INTO sync_configurations
		(id, workspace_id, sync_type, is_active, ad_server, ad_username, ad_password)
		VALUES (?, ?, 'active_directory', 1, 'dc.authsec.test:636', 'svc', 'x')`,
		cfgID.String(), ws.String()).Error)
	svc := &ADInventoryService{DB: db, Production: func() bool { return true }}
	_, err := svc.PutConfig(context.Background(), ws, InventoryConfig{
		ConfigID: cfgID, SkipVerify: true, UseSSL: true,
		Scopes: []InventoryScope{{BaseDN: "DC=authsec,DC=test"}},
	})
	if err == nil || !strings.Contains(err.Error(), "production") {
		t.Fatalf("err = %v", err)
	}
}

type fakeReader struct {
	ident adldap.Identity
	read  func(class string, floor int64) adldap.ClassRead
}

func (f *fakeReader) DirectoryIdentity(context.Context) (adldap.Identity, error) {
	return f.ident, nil
}

func (f *fakeReader) ReadClass(_ context.Context, _, class string, floor int64, _ int) (adldap.ClassRead, error) {
	return f.read(class, floor), nil
}

func obj(class, guid, dn, sam string, disabled bool) adldap.Object {
	return adldap.Object{
		AccountKind: adldap.KindUser, LDAPClass: class, Basis: adldap.BasisObserved,
		ObjectGUID: guid, DistinguishedName: dn, SAMAccountName: sam,
		ObjectSID: "S-1-5-21-1-2-3-4", ObjectClass: []string{"user"},
		AccountFlags: adguid.Flags{
			Raw: map[bool]uint32{true: 514, false: 512}[disabled], AccountDisabled: disabled, Active: !disabled,
		},
		UserAccountControl: map[bool]uint32{true: 514, false: 512}[disabled],
	}
}

func openInventoryDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	stmts := []string{
		`CREATE TABLE sync_configurations (
			id text primary key, workspace_id text, sync_type text, is_active numeric,
			ad_server text, ad_username text, ad_password text, ad_base_dn text,
			ad_use_ssl numeric, ad_skip_verify numeric, ad_ca_bundle text,
			ad_page_size integer, ad_change_tracking numeric, ad_start_tls numeric, ad_tracking_mode text, updated_at datetime)`,
		`CREATE TABLE ad_inventory_scopes (
			id text primary key, workspace_id text, sync_config_id text, integration_scope_id text,
			base_dn text, object_classes text, enabled numeric, created_at datetime, updated_at datetime)`,
		`CREATE TABLE ad_inventory_cursors (
			workspace_id text, scope_id text, invocation_id text, highest_usn integer,
			tracking_mode text, updated_at datetime, primary key (workspace_id, scope_id))`,
		`CREATE TABLE ad_inventory_runs (
			id text primary key, workspace_id text, sync_config_id text, integration_id text, scan_run_id text,
			status text, mode text, started_at datetime, completed_at datetime, requested_by text,
			coverage text, error_text text, objects_seen integer, created_at datetime)`,
		`CREATE TABLE ad_directory_instances (
			id text primary key, workspace_id text, sync_config_id text, forest_id text, domain_sid text,
			domain_dn text, dns_host_name text, invocation_id text, updated_at datetime)`,
		`CREATE TABLE ad_directory_posture (
			id text primary key, workspace_id text not null, run_id text not null, object_guid text not null,
			object_sid text not null default '', account_kind text not null, distinguished_name text not null default '',
			sam_account_name text not null default '', coverage text not null, partial_reasons text not null default '[]',
			unconstrained_delegation numeric not null default 0, constrained_delegation numeric not null default 0,
			protocol_transition numeric not null default 0, delegation_targets text not null default '[]',
			rbcd_principals text not null default '[]', rbcd_asserted numeric not null default 0,
			privileged numeric, privileged_direct numeric not null default 0, privileged_nested numeric not null default 0,
			privileged_path text not null default '[]', admin_count numeric not null default 0, admin_count_orphan numeric,
			sensitive_not_delegated numeric not null default 0, gmsa numeric not null default 0, smsa numeric not null default 0,
			depth_exceeded numeric not null default 0, account_disabled numeric not null default 0, created_at datetime)`,
		`CREATE TABLE iga_integrations (
			id text primary key, workspace_id text, provider text, provider_host text, app_registration_id text,
			installation_id text, account_native_id text, capability_profile text, requested_permissions text,
			granted_permissions text, status text, secret_ref text, verified_at datetime, version integer,
			created_by text, created_at datetime, updated_at datetime)`,
		`CREATE TABLE iga_integration_scopes (
			id text primary key, workspace_id text, integration_id text, estate_scope_id text,
			native_scope_kind text, native_scope_id text, selection_state text, filters text,
			effective_permissions text, created_at datetime, updated_at datetime)`,
		`CREATE TABLE iga_scan_runs (
			id text primary key, workspace_id text, integration_id text, mode text, generation integer,
			status text, requested_by text, normalizer_version text, rule_catalog_version text,
			started_at datetime, completed_at datetime, counters text, failure_code text,
			is_authoritative numeric, created_at datetime)`,
		`CREATE TABLE iga_source_objects (
			id text primary key, workspace_id text, integration_id text, integration_scope_id text,
			object_type text, recognition_key text, native_id text, locator text, normalized_payload text,
			raw_hash text, source_version text, source_subject_key text, scan_generation integer,
			lifecycle text, first_seen_at datetime, last_seen_at datetime, tombstoned_at datetime)`,
		`CREATE TABLE iga_observations (
			id text primary key, workspace_id text, source_object_id text, scan_run_id text, delivery_id text,
			mode text, fact_payload text, evidence_ref text, observed_at datetime, ingested_at datetime,
			normalizer_version text, rule_id text, rule_version text, dedupe_key text)`,
		`CREATE TABLE iga_coverage_states (
			id text primary key, workspace_id text, integration_id text, integration_scope_id text,
			object_class text, state text, reason_code text, last_success_at datetime, last_attempt_at datetime,
			watermark datetime, inspected_count integer, denied_count integer, updated_at datetime)`,
	}
	for _, s := range stmts {
		require.NoError(t, db.Exec(s).Error)
	}
	return db
}
