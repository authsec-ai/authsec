package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/internal/directory/adguid"
	"github.com/authsec-ai/authsec/internal/directory/adldap"
	"github.com/authsec-ai/authsec/services"
	"github.com/authsec-ai/authsec/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestTRD2ITSambaDirectoryPosture seeds delegation and a nested Domain Admins
// member in the local Samba fixture, runs inventory, and reads the posture API.
// It does not run unless AD_SAMBA_TESTS=1. Docker missing is a skip, not a failure.
func TestTRD2ITSambaDirectoryPosture(t *testing.T) {
	if os.Getenv("AD_SAMBA_TESTS") != "1" {
		t.Skip("set AD_SAMBA_TESTS=1 to build and run the Samba AD DC fixture")
	}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skip("AD_SAMBA_TESTS=1 but /var/run/docker.sock is not available")
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture path")
	}
	fixture := filepath.Join(filepath.Dir(file), "..", "fixtures", "samba")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{Context: fixture, Dockerfile: "Dockerfile"},
			ExposedPorts:   []string{"389/tcp"},
			Privileged:     true,
			Hostname:       "dc.authsec.test",
			WaitingFor:     wait.ForLog("AUTHSEC_AD_READY").WithStartupTimeout(6 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("samba fixture: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatal(err)
	}
	addr := host + ":" + port.Port()
	const bindUser = "Administrator@AUTHSEC.TEST"
	const bindPass = "CANARY-SECRET-DO-NOT-LEAK-1"

	lconn, err := ldap.DialURL("ldap://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	defer lconn.Close()
	if err := lconn.Bind(bindUser, bindPass); err != nil {
		t.Fatal(err)
	}
	base := ldapBase(t, lconn)
	unconSID := ldapSID(t, lconn, base, "unconstrained")
	replaceAttr(t, lconn, ldapDN(t, lconn, base, "unconstrained"), "userAccountControl", []string{uac(512 | adguid.UACTrustedForDelegation)})
	replaceAttr(t, lconn, ldapDN(t, lconn, base, "constrained"), "userAccountControl", []string{uac(512 | adguid.UACTrustedToAuthForDelegation)})
	replaceAttr(t, lconn, ldapDN(t, lconn, base, "constrained"), "msDS-AllowedToDelegateTo", []string{"HOST/db.authsec.test"})
	sd, err := adguid.SelfRelativeSD([]string{unconSID})
	if err != nil {
		t.Fatal(err)
	}
	replaceAttr(t, lconn, ldapDN(t, lconn, base, "rbcdtarget"), "msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sd)})
	replaceAttr(t, lconn, ldapDN(t, lconn, base, "orphan"), "adminCount", []string{"1"})
	replaceAttr(t, lconn, ldapDN(t, lconn, base, "sensitive"), "userAccountControl", []string{uac(512 | adguid.UACNotDelegated)})

	db := openSambaInventoryDB(t)
	ws, cfgID := uuid.New(), uuid.New()
	enc, err := utils.Encrypt(bindPass)
	require.NoError(t, err)
	require.NoError(t, db.Exec(`INSERT INTO sync_configurations
		(id, workspace_id, sync_type, is_active, ad_server, ad_username, ad_password, ad_use_ssl, ad_page_size, ad_change_tracking, ad_tracking_mode)
		VALUES (?, ?, 'active_directory', 1, ?, ?, ?, 0, 200, 0, 'usn')`,
		cfgID.String(), ws.String(), addr, bindUser, enc).Error)
	svc := &services.ADInventoryService{DB: db}
	_, err = svc.PutConfig(ctx, ws, services.InventoryConfig{
		ConfigID: cfgID, Server: addr, Username: bindUser, PageSize: 200,
		Scopes: []services.InventoryScope{{
			BaseDN: base, ObjectClasses: []string{adldap.ClassUser, adldap.ClassGroup}, Enabled: true,
		}},
	})
	require.NoError(t, err)
	view, err := svc.Run(ctx, ws, cfgID, "tester")
	require.NoError(t, err)
	if view.Status != "succeeded" {
		t.Fatalf("inventory %s: %s coverage=%+v", view.Status, view.Error, view.Coverage)
	}

	gin.SetMode(gin.TestMode)
	h := &shared.ADInventoryController{Svc: svc}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("workspace_id", ws.String())
		c.Next()
	})
	r.GET("/runs/:id/posture", h.ListPosture)
	var all []services.PostureView
	offset := 0
	for {
		req := httptest.NewRequest(http.MethodGet, "/runs/"+view.ID.String()+"/posture?limit=50&offset="+strconv.Itoa(offset), nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		if strings.Contains(strings.ToLower(rec.Body.String()), "msds-managedpassword") {
			t.Fatal("posture API named a secret attribute")
		}
		var page services.PosturePage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
		all = append(all, page.Posture...)
		if page.NextOffset == nil {
			break
		}
		offset = *page.NextOffset
	}
	bySAM := map[string]services.PostureView{}
	for _, row := range all {
		bySAM[row.SAMAccountName] = row
	}
	need := func(sam string) services.PostureView {
		t.Helper()
		row, ok := bySAM[sam]
		if !ok {
			t.Fatalf("no posture for %s (%d rows)", sam, len(all))
		}
		return row
	}
	if row := need("unconstrained"); !row.UnconstrainedDelegation || row.Coverage != "complete" {
		t.Fatalf("unconstrained: %+v", row)
	}
	if row := need("constrained"); !row.ConstrainedDelegation || !row.ProtocolTransition || !contains(row.DelegationTargets, "HOST/db.authsec.test") {
		t.Fatalf("constrained: %+v", row)
	}
	if row := need("rbcdtarget"); !row.RBCDAsserted || !contains(row.RBCDPrincipals, unconSID) {
		t.Fatalf("rbcd: %+v", row)
	}
	if row := need("nestedda"); row.Coverage != "complete" || row.Privileged == nil || !*row.Privileged || !row.PrivilegedNested {
		t.Fatalf("nested domain admin: %+v", row)
	} else if !pathHasRID(row.PrivilegedPath, "512") {
		t.Fatalf("nested path %v does not reach RID 512", row.PrivilegedPath)
	}
	if row := need("orphan"); row.Coverage != "complete" || !row.AdminCount || row.AdminCountOrphan == nil || !*row.AdminCountOrphan || row.Privileged == nil || *row.Privileged {
		t.Fatalf("orphan: %+v", row)
	}
	if row := need("sensitive"); !row.SensitiveNotDelegated {
		t.Fatalf("sensitive: %+v", row)
	}
}

func uac(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func pathHasRID(path []string, rid string) bool {
	for _, sid := range path {
		if strings.HasSuffix(sid, "-"+rid) {
			return true
		}
	}
	return false
}

func ldapBase(t *testing.T, conn *ldap.Conn) string {
	t.Helper()
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"defaultNamingContext"}, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		t.Fatalf("rootDSE: %v", err)
	}
	base := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if base == "" {
		t.Fatal("rootDSE returned no defaultNamingContext")
	}
	return base
}

func ldapDN(t *testing.T, conn *ldap.Conn, base, sam string) string {
	t.Helper()
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		"(sAMAccountName="+sam+")", []string{"distinguishedName"}, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		t.Fatalf("find %s: %v", sam, err)
	}
	return res.Entries[0].DN
}

func ldapSID(t *testing.T, conn *ldap.Conn, base, sam string) string {
	t.Helper()
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		"(sAMAccountName="+sam+")", []string{"objectSid"}, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		t.Fatalf("sid %s: %v", sam, err)
	}
	sid, err := adguid.ParseSID(res.Entries[0].GetRawAttributeValue("objectSid"))
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func replaceAttr(t *testing.T, conn *ldap.Conn, dn, attr string, values []string) {
	t.Helper()
	m := ldap.NewModifyRequest(dn, nil)
	m.Replace(attr, values)
	if err := conn.Modify(m); err != nil {
		t.Fatalf("modify %s %s: %v", dn, attr, err)
	}
}

func openSambaInventoryDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	for _, s := range []string{
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
			sensitive_not_delegated numeric not null default 0, protected_users numeric not null default 0, gmsa numeric not null default 0, smsa numeric not null default 0,
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
	} {
		require.NoError(t, db.Exec(s).Error)
	}
	return db
}
