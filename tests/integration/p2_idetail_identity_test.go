package integration

// GET /identities/:id (§5.3, T6.3): the list row plus continuity,
// immutable_key, D-85's provider_attrs allowlist, a user's access keys
// (D-86) and sources -- for a role, a user and a group scanned through the
// real pipeline; a retired identity readable (E8); and E14's 404s.

import (
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

func TestP2IdetailIdentityOverview(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-overview", true)
	a := l.account(accountA)
	boundary := a.managed("RoleCeiling", s3aDoc("Ceiling", "s3:*", "*"))
	// A trust document with a Deny and a NotAction statement: the flags are
	// rendered (D-44), the NotAction keys (trust_negated_statements) are NOT
	// in the allowlist (D-85).
	shared := trustRole(a, "SharedToolRole", "AROASHAREDTOOLROLE01", trustDoc(
		trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole"),
		`{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::`+trustAccountC+`:root"},"Action":"sts:AssumeRole"}`,
		`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::`+trustAccountC+`:root"},"NotAction":"sts:TagSession"}`))
	s3aEditRole(t, a, "SharedToolRole", func(r *iamtypes.Role) {
		r.Tags = []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("support")}}
		r.PermissionsBoundary = s3aBoundary(boundary)
	})
	listsFunctions(a, "us-east-1", "ticket-tools", shared, "refund-tools", shared)
	s3aUser(a, "ci-deployer", "AIDACIDEPLOYER000001")
	a.iam.keys["ci-deployer"] = []iamtypes.AccessKeyMetadata{
		{AccessKeyId: aws.String("AKIAIDETAILACTIVE001"), UserName: aws.String("ci-deployer"),
			Status: iamtypes.StatusTypeActive, CreateDate: ago(400 * 24 * time.Hour)},
		{AccessKeyId: aws.String("AKIAIDETAILINACTIVE1"), UserName: aws.String("ci-deployer"),
			Status: iamtypes.StatusTypeInactive, CreateDate: ago(30 * 24 * time.Hour)},
	}
	a.iam.keyLastUse["AKIAIDETAILACTIVE001"] = ago(3 * 24 * time.Hour)
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	l.scanAndProject(a)
	api := l.api()

	roleID := idetailIdentityID(t, l, "SharedToolRole")
	body := idetailGet(t, api, "/identities/"+roleID.String())
	d := dig(body, "data").(map[string]any)

	// The list row, verbatim: every field the list shows is on the detail with
	// the same value (§2.14.11 -- a row and the object it opens never disagree).
	list := idetailGet(t, api, "/identities"+qs("q", "SharedToolRole"))
	row := listsRowBy(t, digl(list, "data"), "ref", refOf("identity", roleID))
	for k, v := range row {
		if idetailJSON(d[k]) != idetailJSON(v) {
			t.Errorf("detail %s = %s, list row says %s", k, idetailJSON(d[k]), idetailJSON(v))
		}
	}
	if num(d, "used_by_count", "value") != 2 || dig(d, "used_by_count", "exact") != true {
		t.Errorf("used_by_count = %v, want {2, exact}: two Lambdas run as it", d["used_by_count"])
	}
	if digs(d, "region") != "global" || digs(d, "kind") != models.CloudIdentityIAMRole ||
		digs(d, "arn") != shared || digs(d, "account", "id") != accountA || dig(d, "account", "connected") != true {
		t.Errorf("role detail = %s, want region global, kind iam_role, its ARN and account %s", idetailJSON(d), accountA)
	}
	if digs(d, "continuity") != models.ContinuityImmutable || digs(d, "immutable_key") != "AROASHAREDTOOLROLE01" {
		t.Errorf("continuity/immutable_key = %v/%v, want immutable/AROASHAREDTOOLROLE01", d["continuity"], d["immutable_key"])
	}
	if digs(d, "lifecycle") != models.IGALifecycleActive || digs(d, "state") != "current" ||
		digs(d, "first_seen_at") == "" || digs(d, "last_confirmed_at") == "" {
		t.Errorf("role detail lifecycle/state/dates = %s", idetailJSON(d))
	}

	// provider_attrs: D-85's allowlist, exactly.
	pa := dig(d, "provider_attrs").(map[string]any)
	keys := make([]string, 0, len(pa))
	for k := range pa {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "path,permissions_boundary_arn,tags,trust_has_deny,trust_has_not_principal" {
		t.Errorf("role provider_attrs keys = %v, want exactly D-85's allowlist (never trust_negated_statements or raw jsonb)", keys)
	}
	if pa["trust_has_deny"] != true || pa["trust_has_not_principal"] != false ||
		pa["permissions_boundary_arn"] != boundary || digs(pa, "tags", "team") != "support" || pa["path"] != "/" {
		t.Errorf("role provider_attrs = %s, want deny true, not_principal false, its boundary, tags and path", idetailJSON(pa))
	}
	if _, has := d["credentials"]; has {
		t.Errorf("a role carries credentials %v: only users hold access keys", d["credentials"])
	}

	// sources: its one support row, as the presence claim that names it.
	srcs := digl(d, "sources")
	var supportID uuid.UUID
	l.db.Raw(`SELECT id FROM iga_object_support WHERE workspace_id = ? AND identity_account_id = ?`, l.ws, roleID).Row().Scan(&supportID)
	if len(srcs) != 1 || digs(srcs[0], "presence") != refOf("presence", supportID) ||
		digs(srcs[0], "integration") != refOf("cloud_connector", a.conn) || digs(srcs[0], "state") != "current" ||
		digs(srcs[0], "account", "id") != accountA || dig(srcs[0], "ended_reason") != nil || digs(srcs[0], "last_confirmed_at") == "" {
		t.Errorf("sources = %s, want its one current support row from connector %s", idetailJSON(srcs), a.conn)
	}
	if digs(body, "meta", "graph_state") != "published" || num(body, "meta", "rev") < 1 || digl(body, "meta", "coverage") == nil {
		t.Errorf("meta = %s, want the detail envelope with rev and coverage []", idetailJSON(body["meta"]))
	}

	// The user: its keys (D-86), status AWS's own, lifecycle beside it.
	userID := idetailIdentityID(t, l, "ci-deployer")
	u := dig(idetailGet(t, api, "/identities/"+userID.String()), "data")
	creds := digl(u, "credentials")
	if len(creds) != 2 {
		t.Fatalf("credentials = %s, want both keys", idetailJSON(creds))
	}
	active := idetailByRef(t, creds, "AKIAIDETAILACTIVE001", "key_id")
	inactive := idetailByRef(t, creds, "AKIAIDETAILINACTIVE1", "key_id")
	if active["status"] != "Active" || active["lifecycle"] != "active" || digs(active, "last_used_at") == "" {
		t.Errorf("active key = %v, want status Active (AWS's spelling, D-86), lifecycle active, its last use", active)
	}
	if inactive["status"] != "Inactive" || inactive["lifecycle"] != "revoked" || inactive["last_used_at"] != nil {
		t.Errorf("inactive key = %v, want status Inactive (lifecycle revoked), never used -> null", inactive)
	}
	for _, c := range creds {
		if _, has := c.(map[string]any)["created_at"]; !has || digs(c, "last_seen_at") == "" {
			t.Errorf("credential %v: want created_at (null until the projector records issued_at) and last_seen_at", c)
		}
	}
	// A user has no trust document: its trust flags are stated, as null --
	// never false, never absent (D-85's one shape, D-102d).
	upa := dig(u, "provider_attrs").(map[string]any)
	for _, k := range []string{"trust_has_deny", "trust_has_not_principal"} {
		if v, has := upa[k]; !has || v != nil {
			t.Errorf("user provider_attrs = %v: %s must be present and null", upa, k)
		}
	}

	// The group: no credentials; trust flags null, like the user's.
	groupID := idetailIdentityID(t, l, "ops")
	g := dig(idetailGet(t, api, "/identities/identity:"+groupID.String()), "data").(map[string]any)
	if _, has := g["credentials"]; has || digs(g, "kind") != models.CloudIdentityIAMGroup || digs(g, "immutable_key") != "AGPAOPSOPSOPSOPSOPS1" {
		t.Errorf("group detail = %s, want kind iam_group, its GroupId, no credentials", idetailJSON(g))
	}
	gpa := dig(g, "provider_attrs").(map[string]any)
	for _, k := range []string{"trust_has_deny", "trust_has_not_principal"} {
		if v, has := gpa[k]; !has || v != nil {
			t.Errorf("group provider_attrs = %v: %s must be present and null", gpa, k)
		}
	}
}

// A key that turns Inactive: ONE entry, status Inactive. The projector once
// inserted a new 'revoked' row beside the frozen 'active' one on every pass
// (the credential defect D-64 fixed); the read must still report the latest
// reading of such a pair, never the key twice.
func TestP2IdetailCredentialTurnsInactive(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-creds", true)
	a := l.account(accountA)
	s3aUser(a, "ci-deployer", "AIDACIDEPLOYER000001")
	key := iamtypes.AccessKeyMetadata{AccessKeyId: aws.String("AKIAIDETAILROTATE001"), UserName: aws.String("ci-deployer"),
		Status: iamtypes.StatusTypeActive, CreateDate: ago(100 * 24 * time.Hour)}
	a.iam.keys["ci-deployer"] = []iamtypes.AccessKeyMetadata{key}
	l.scanAndProject(a)
	key.Status = iamtypes.StatusTypeInactive
	a.iam.keys["ci-deployer"] = []iamtypes.AccessKeyMetadata{key}
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)

	userID := idetailIdentityID(t, l, "ci-deployer")
	// D-64's projector fix keeps ONE row per key (TestP2BdbInactiveKeyKeepsOneRow
	// proves it). A build before the fix left the frozen 'active' original
	// beside the 'revoked' reading, and the read still guards against it -- so
	// that pre-fix state, which the fixed pipeline cannot produce, is inserted
	// directly: the fixture must really hold the key twice, or this proves
	// nothing about the read.
	if n := l.count(`SELECT count(*) FROM iga_credentials WHERE workspace_id = ? AND identity_account_id = ?
	                   AND key_identifier = 'AKIAIDETAILROTATE001'`, l.ws, userID); n != 1 {
		t.Fatalf("setup: %d rows for the key after the fixed projector, want 1", n)
	}
	if err := l.db.Exec(`INSERT INTO iga_credentials (workspace_id, identity_account_id, credential_type, issuer,
	                            key_identifier, rotation_posture, lifecycle, provider, source_key, continuity,
	                            first_seen_at, last_seen_at, created_at, updated_at)
	                     SELECT workspace_id, identity_account_id, credential_type, issuer, key_identifier,
	                            rotation_posture, 'active', provider, source_key, continuity, first_seen_at,
	                            first_seen_at, first_seen_at, first_seen_at
	                       FROM iga_credentials WHERE workspace_id = ? AND identity_account_id = ?`,
		l.ws, userID).Error; err != nil {
		t.Fatalf("setup: insert the pre-D-64 duplicate: %v", err)
	}
	creds := digl(idetailGet(t, l.api(), "/identities/"+userID.String()), "data", "credentials")
	if len(creds) != 1 || digs(creds[0], "status") != "Inactive" || digs(creds[0], "lifecycle") != "revoked" {
		t.Errorf("credentials = %s, want the key ONCE, inactive", idetailJSON(creds))
	}
}

// E8: a role deleted and recreated under the same name. The old identity is
// readable -- retired, reason recreated, its source ended -- and so are its
// tabs, which say whose they are rather than rendering empty (§2.14.5).
func TestP2IdetailRetiredIdentityReadable(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-retired", true)
	a := l.account(accountA)
	shared := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	listsFunctions(a, "us-east-1", "ticket-tools", shared)
	l.scanAndProject(a)
	oldID := idetailIdentityID(t, l, "SharedToolRole")
	a.role("SharedToolRole", "AROASHAREDTOOLROLE02") // recreated: a new RoleId
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)
	api := l.api()

	d := dig(idetailGet(t, api, "/identities/"+oldID.String()), "data").(map[string]any)
	if digs(d, "lifecycle") != models.IGALifecycleRetired || digs(d, "retired_reason") != models.RetiredRecreated ||
		digs(d, "immutable_key") != "AROASHAREDTOOLROLE01" || digs(d, "last_confirmed_at") == "" {
		t.Errorf("old identity = %s, want retired recreated, its own RoleId and last confirmation", idetailJSON(d))
	}
	newID := idetailIdentityID(t, l, "SharedToolRole")
	if newID == oldID {
		t.Fatal("setup: the recreation reused the old id")
	}
	// Its tabs name it, retired, so the console can say "no current data".
	ub := idetailGet(t, api, "/identities/"+oldID.String()+"/used-by")
	if digs(ub, "data", "identity", "lifecycle") != models.IGALifecycleRetired || len(digl(ub, "data", "workloads", "items")) != 0 {
		t.Errorf("retired role's used-by = %s, want the retired header and no current workloads", idetailJSON(ub["data"]))
	}
	// With include_ended the ended executes_as shows, ended subject_recreated.
	ended := digl(idetailGet(t, api, "/identities/"+oldID.String()+"/used-by"+qs("include_ended", "true")), "data", "workloads", "items")
	if len(ended) != 1 || digs(ended[0], "state") != "ended" || digs(ended[0], "ended_reason") != models.EndedSubjectRecreate ||
		digs(ended[0], "valid_to") == "" {
		t.Errorf("retired role's ended uses = %s, want the one executes_as ended subject_recreated", idetailJSON(ended))
	}
	perm := idetailGet(t, api, "/identities/"+oldID.String()+"/permissions")
	if digs(perm, "data", "identity", "lifecycle") != models.IGALifecycleRetired ||
		digs(perm, "data", "activity", "state") != "not_collected" || digs(perm, "data", "activity", "reason") != "retired" {
		t.Errorf("retired role's permissions = %s, want the retired header and activity not collected (retired)", idetailJSON(perm["data"]))
	}
}

// E14 and D-4..D-6: 404 not_found, with no hint, on every identity and
// external-principal route -- for another workspace's ids, a GitHub identity,
// an AWS row no pass supported, a malformed id, another type's reference, and
// before anything is published. And 400 for a parameter the route does not
// take.
func TestP2IdetailNotFound(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-404", true)
	a := l.account(accountA)
	a.role("HomeRole", "AROAHOMEROLEHOMEROLE")
	l.scanAndProject(a)
	homeID := idetailIdentityID(t, l, "HomeRole")
	homeExt := idetailExternalID(t, l, "aws", "lambda.amazonaws.com")

	// A GitHub identity WITH a support row, and an AWS row with none (D-6).
	var github, orphan uuid.UUID
	if err := l.db.Raw(`WITH gh AS (
	                        INSERT INTO iga_identity_accounts (workspace_id, display_name, account_kind, provider, source_key)
	                        VALUES (?, 'HomeRole', 'github_user', 'github', 'github␟user␟idetail')
	                        RETURNING workspace_id, id),
	                      s AS (INSERT INTO iga_object_support (workspace_id, identity_account_id, connector_id, partition_key, state)
	                            SELECT workspace_id, id, ?, 'idetail|github', 'current' FROM gh)
	                    SELECT id FROM gh`, l.ws, a.conn).Row().Scan(&github); err != nil {
		t.Fatalf("seed github identity: %v", err)
	}
	if err := l.db.Raw(`INSERT INTO iga_identity_accounts (workspace_id, display_name, account_kind, provider, source_key)
	                    VALUES (?, 'OrphanRole', 'iam_role', 'aws', 'aws' || chr(31) || 'arn:aws:iam::`+accountA+`:role/OrphanRole')
	                    RETURNING id`, l.ws).Row().Scan(&orphan); err != nil {
		t.Fatalf("seed unsupported identity: %v", err)
	}

	// Another workspace, scanned: its ids exist, just not here.
	l2 := idetailSecondLab(t, l, "p2-idetail-404-other")
	b := l2.account(accountB)
	b.role("OtherRole", "AROAOTHERROLEOTHERRO")
	l2.scanAndProject(b)
	otherID := idetailIdentityID(t, l2, "OtherRole")
	otherExt := idetailExternalID(t, l2, "aws", "lambda.amazonaws.com")

	api := l.api()
	notFound := func(path string) {
		t.Helper()
		code, body := api.get(path)
		if code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Errorf("GET %s = %d %s, want 404 not_found", path, code, idetailJSON(body))
			return
		}
		if len(dig(body, "error").(map[string]any)) != 2 {
			t.Errorf("GET %s 404 body = %s: no hint beyond code and message", path, idetailJSON(body))
		}
	}
	for _, tab := range []string{"", "/used-by", "/permissions"} {
		for _, id := range []string{otherID.String(), github.String(), orphan.String(), "not-a-uuid",
			"workload:" + homeID.String(), "identity:" + otherID.String(), uuid.NewString()} {
			notFound("/identities/" + id + tab)
		}
		idetailGet(t, api, "/identities/identity:"+homeID.String()+tab)
	}
	for _, tab := range []string{"", "/referenced-by"} {
		for _, id := range []string{otherExt.String(), homeID.String(), "identity:" + homeExt.String(), "nope"} {
			notFound("/external-principals/" + id + tab)
		}
		idetailGet(t, api, "/external-principals/external_principal:"+homeExt.String()+tab)
	}
	// The same ids are readable from their own workspace.
	api.asWorkspace(l2.ws)
	idetailGet(t, api, "/identities/"+otherID.String())
	idetailGet(t, api, "/external-principals/"+otherExt.String())
	api.asWorkspace(l.ws)

	// 400 names the parameter the route does not take (checked before the
	// snapshot, D-10); a bad include_ended or limit is 400 too.
	for path, param := range map[string]string{
		"/identities/" + homeID.String() + qs("sort", "name"):                            "sort",
		"/identities/" + homeID.String() + "/permissions" + qs("cursor", "x"):            "cursor",
		"/identities/" + homeID.String() + "/used-by" + qs("include_ended", "1"):         "include_ended",
		"/external-principals/" + homeExt.String() + "/referenced-by" + qs("limit", "0"): "limit",
		"/external-principals/" + homeExt.String() + qs("section", "workloads"):          "section",
	} {
		code, body := api.get(path)
		if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" || digs(body, "error", "parameter") != param {
			t.Errorf("GET %s = %d %s, want 400 invalid_parameter naming %s", path, code, idetailJSON(body), param)
		}
	}

	// Nothing published yet: 404 (D-4), even for an id that will exist.
	l3 := idetailSecondLab(t, l, "p2-idetail-404-unpublished")
	api.asWorkspace(l3.ws)
	notFound("/identities/" + uuid.NewString())
	notFound("/external-principals/" + uuid.NewString() + "/referenced-by")
}
