package integration

import (
	"testing"

	"github.com/authsec-ai/authsec/internal/directory/adresolve"
	"github.com/google/uuid"
)

const (
	a9Forest   = "DC=authsec,DC=test"
	a9Domain   = "S-1-5-21-1-2-3"
	a9User     = "11111111-1111-1111-1111-111111111111"
	a9UserSID  = "S-1-5-21-1-2-3-1101"
	a9GroupSID = "S-1-5-21-1-2-3-513"
)

func (f *a3) seedDirectoryInstance(forest, domainSID, domainDN string) {
	f.t.Helper()
	cfg := uuid.New()
	f.exec(`INSERT INTO sync_configurations
		(id, workspace_id, client_id, sync_type, config_name, ad_tracking_mode)
		VALUES ($1, $2, $3, 'active_directory', $4, 'usn')`,
		cfg, f.ws, uuid.New(), "ad-"+cfg.String()[:8])
	f.exec(`INSERT INTO ad_directory_instances
		(id, workspace_id, sync_config_id, forest_id, domain_sid, domain_dn, dns_host_name)
		VALUES ($1, $2, $3, $4, $5, $6, 'dc.authsec.test')`,
		uuid.New(), f.ws, cfg, forest, domainSID, domainDN)
}

func (f *a3) projectAD(integ, collector uuid.UUID, guid, sid, name, dn, kind string, disabled bool) {
	f.t.Helper()
	run := f.seedRun(integ, "runtime_batch", false)
	body := map[string]any{
		"account_kind": kind, "object_guid": guid, "object_sid": sid,
		"distinguished_name": dn, "sam_account_name": name, "display_name": name,
		"forest_id": a9Forest,
	}
	if disabled {
		body["account_flags"] = map[string]any{"account_disabled": true}
	}
	objectType := "user"
	if kind == "ad_group" {
		objectType = "group"
	}
	f.seedFact(integ, run, objectType, guid, "", body, nil)
	f.seedBatch(integ, collector, uuid.New(), run, 1, uuid.Nil)
	f.projectDefault()
}

func (f *a3) projectLocalSnapshot(integ, collector uuid.UUID, facts []localFact) {
	f.t.Helper()
	epoch := uuid.New()
	snap := f.seedSnapshot(collector, epoch, "host", "linux.local_account", true, 1)
	run := f.seedRun(integ, "configuration_snapshot", true)
	for _, fact := range facts {
		native := map[string]any{"uid": fact.uid, "user_namespace": "host"}
		for k, v := range fact.native {
			native[k] = v
		}
		f.seedFact(integ, run, "linux.local_account", fact.ref, fact.ref,
			map[string]any{"native": native, "attributes": map[string]any{"name": fact.name}}, nil)
	}
	f.seedBatch(integ, collector, epoch, run, 1, snap)
	f.projectDefault()
}

type localFact struct {
	ref, name string
	uid       int
	native    map[string]any
}

func TestTRD2ITA9P2MappedAccountLinksDerived(t *testing.T) {
	f := newA3(t)
	f.seedDirectoryInstance(a9Forest, a9Domain, a9Forest)
	ad, adCol, _ := f.seedCollector("ad")
	f.projectAD(ad, adCol, a9User, a9UserSID, "alice", "CN=alice,DC=authsec,DC=test", "ad_user", false)
	f.projectAD(ad, adCol, "33333333-3333-3333-3333-333333333333", a9GroupSID, "eng", "CN=eng,DC=authsec,DC=test", "ad_group", false)

	linux, col, _ := f.seedCollector("linux")
	epoch := uuid.New()
	snap := f.seedSnapshot(col, epoch, "host", "linux.local_account", true, 1)
	run := f.seedRun(linux, "configuration_snapshot", true)
	f.seedFact(linux, run, "linux.local_account", "alice", "alice", map[string]any{
		"native": map[string]any{
			"uid": 1000, "user_namespace": "host",
			"directory_guid": a9User, "directory_sid": a9UserSID,
			"directory_domain": a9Forest, "mapping_source": "sssd",
		},
		"attributes": map[string]any{"name": "alice"},
	}, nil)
	f.seedFact(linux, run, "linux.local_group", "eng", "eng", map[string]any{
		"native": map[string]any{
			"gid": 10, "user_namespace": "host",
			"directory_sid": a9GroupSID, "mapping_source": "winbind",
		},
		"attributes": map[string]any{"name": "eng"},
	}, nil)
	f.seedBatch(linux, col, epoch, run, 1, snap)
	f.projectDefault()

	if f.scalar(`SELECT count(*) FROM iga_relationship
		WHERE workspace_id = $1 AND relationship_type = 'backed_by_directory' AND state = 'current'
		  AND basis = 'derived' AND derivation_rule = $2`, f.ws, adresolve.Rule("sssd")) != 1 {
		t.Fatal("sssd user link missing")
	}
	if f.scalar(`SELECT count(*) FROM iga_relationship
		WHERE workspace_id = $1 AND relationship_type = 'backed_by_directory' AND state = 'current'
		  AND basis = 'derived' AND derivation_rule = $2`, f.ws, adresolve.Rule("winbind")) != 1 {
		t.Fatal("winbind group link missing")
	}
	if f.scalar(`SELECT count(*) FROM iga_relationship_evidence e
		JOIN iga_relationship r ON r.workspace_id = e.workspace_id AND r.id = e.relationship_id
		WHERE r.workspace_id = $1 AND r.relationship_type = 'backed_by_directory'
		  AND e.relation = 'supports' AND e.iga_observation_id IS NOT NULL`, f.ws) != 2 {
		t.Fatal("mapping evidence missing")
	}
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'linux'`, f.ws) != 2 {
		t.Fatal("local rows were replaced by the directory rows")
	}
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'ad'`, f.ws) != 2 {
		t.Fatal("directory rows missing")
	}
}

func TestTRD2ITA9P2SameNameStaysSeparate(t *testing.T) {
	f := newA3(t)
	f.seedDirectoryInstance(a9Forest, a9Domain, a9Forest)
	ad, adCol, _ := f.seedCollector("ad")
	f.projectAD(ad, adCol, a9User, a9UserSID, "alice", "CN=alice,DC=authsec,DC=test", "ad_user", false)
	linux, col, _ := f.seedCollector("linux")
	f.projectLocalSnapshot(linux, col, []localFact{{ref: "alice", name: "alice", uid: 1000}})
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND display_name = 'alice'`, f.ws) != 2 {
		t.Fatal("same-name pair was collapsed")
	}
	if f.scalar(`SELECT count(*) FROM iga_relationship WHERE workspace_id = $1 AND relationship_type = 'backed_by_directory'`, f.ws) != 0 {
		t.Fatal("name similarity created a directory link")
	}
}

func TestTRD2ITA9P2ADRenameKeepsLink(t *testing.T) {
	f := newA3(t)
	f.seedDirectoryInstance(a9Forest, a9Domain, a9Forest)
	ad, adCol, _ := f.seedCollector("ad")
	f.projectAD(ad, adCol, a9User, a9UserSID, "alice", "CN=alice,DC=authsec,DC=test", "ad_user", false)
	linux, col, _ := f.seedCollector("linux")
	mapping := map[string]any{
		"directory_guid": a9User, "directory_domain": a9Forest, "mapping_source": "sssd",
	}
	f.projectLocalSnapshot(linux, col, []localFact{{ref: "alice", name: "alice", uid: 1000, native: mapping}})
	var rel, target uuid.UUID
	var adKey string
	f.scan(`SELECT r.id, r.target_identity_account_id, a.source_key
		FROM iga_relationship r
		JOIN iga_identity_accounts a ON a.workspace_id = r.workspace_id AND a.id = r.target_identity_account_id
		WHERE r.workspace_id = $1 AND r.relationship_type = 'backed_by_directory' AND r.state = 'current'`,
		[]any{f.ws}, &rel, &target, &adKey)

	f.projectAD(ad, adCol, a9User, a9UserSID, "alice-renamed", "CN=alice-renamed,DC=authsec,DC=test", "ad_user", false)
	f.projectLocalSnapshot(linux, col, []localFact{{ref: "alice", name: "alice", uid: 1000, native: mapping}})

	var rel2, target2 uuid.UUID
	var adKey2, name string
	f.scan(`SELECT r.id, r.target_identity_account_id, a.source_key, a.display_name
		FROM iga_relationship r
		JOIN iga_identity_accounts a ON a.workspace_id = r.workspace_id AND a.id = r.target_identity_account_id
		WHERE r.workspace_id = $1 AND r.state = 'current' AND r.relationship_type = 'backed_by_directory'`,
		[]any{f.ws}, &rel2, &target2, &adKey2, &name)
	if rel2 != rel || target2 != target || adKey2 != adKey || name != "alice-renamed" {
		t.Fatalf("rename rel %s->%s target %s->%s key %s->%s name %s", rel, rel2, target, target2, adKey, adKey2, name)
	}
}

func TestTRD2ITA9P2DisabledAccountResolves(t *testing.T) {
	f := newA3(t)
	f.seedDirectoryInstance(a9Forest, a9Domain, a9Forest)
	ad, adCol, _ := f.seedCollector("ad")
	f.projectAD(ad, adCol, a9User, a9UserSID, "off", "CN=off,DC=authsec,DC=test", "ad_user", true)
	linux, col, _ := f.seedCollector("linux")
	f.projectLocalSnapshot(linux, col, []localFact{{
		ref: "off", name: "off", uid: 1001,
		native: map[string]any{"directory_guid": a9User, "directory_domain": a9Forest, "mapping_source": "sssd"},
	}})
	if f.scalar(`SELECT count(*) FROM iga_relationship r
		JOIN iga_identity_accounts a ON a.workspace_id = r.workspace_id AND a.id = r.target_identity_account_id
		WHERE r.workspace_id = $1 AND r.relationship_type = 'backed_by_directory' AND r.state = 'current'
		  AND a.account_state = 'disabled' AND a.lifecycle = 'active'`, f.ws) != 1 {
		t.Fatal("disabled directory account did not resolve")
	}
}

func TestTRD2ITA9P2UnknownDirectoryInstance(t *testing.T) {
	f := newA3(t)
	f.seedDirectoryInstance(a9Forest, a9Domain, a9Forest)
	ad, adCol, _ := f.seedCollector("ad")
	f.projectAD(ad, adCol, a9User, a9UserSID, "alice", "CN=alice,DC=authsec,DC=test", "ad_user", false)
	linux, col, _ := f.seedCollector("linux")
	f.projectLocalSnapshot(linux, col, []localFact{{
		ref: "alice", name: "alice", uid: 1000,
		native: map[string]any{
			"directory_guid": a9User, "directory_domain": "DC=missing,DC=test", "mapping_source": "sssd",
		},
	}})
	if f.batchState(f.latestRun(linux)) != "published" {
		t.Fatal("unresolved mapping failed the pass")
	}
	if f.scalar(`SELECT count(*) FROM iga_relationship WHERE workspace_id = $1 AND relationship_type = 'backed_by_directory'`, f.ws) != 0 {
		t.Fatal("unknown directory instance still linked")
	}
	var coverage string
	f.scan(`SELECT coverage_state FROM iga_projection_state
		WHERE workspace_id = $1 AND integration_id = $2 AND object_class = 'linux.local_account'`,
		[]any{f.ws, linux}, &coverage)
	if coverage != "reached" {
		t.Fatalf("coverage %s", coverage)
	}
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = $1 AND provider = 'linux' AND display_name = 'alice'`, f.ws) != 1 {
		t.Fatal("local account missing after an unresolved mapping")
	}
}

func TestTRD2ITA9P2MappingEndsAndSurvivesSilence(t *testing.T) {
	f := newA3(t)
	f.seedDirectoryInstance(a9Forest, a9Domain, a9Forest)
	ad, adCol, _ := f.seedCollector("ad")
	f.projectAD(ad, adCol, a9User, a9UserSID, "alice", "CN=alice,DC=authsec,DC=test", "ad_user", false)
	linux, col, _ := f.seedCollector("linux")
	mapping := map[string]any{"directory_guid": a9User, "directory_domain": a9Forest, "mapping_source": "sssd"}
	f.projectLocalSnapshot(linux, col, []localFact{{ref: "alice", name: "alice", uid: 1000, native: mapping}})
	if f.scalar(`SELECT count(*) FROM iga_relationship WHERE workspace_id = $1 AND state = 'current' AND relationship_type = 'backed_by_directory'`, f.ws) != 1 {
		t.Fatal("link was not created")
	}

	run := f.seedRun(linux, "runtime_batch", false)
	f.seedFact(linux, run, "linux.process_group", "g", "g",
		map[string]any{"native": map[string]any{"boot_id": "boot", "root_pid": "10", "start_ticks": "1"}}, nil)
	f.seedBatch(linux, col, uuid.New(), run, 1, uuid.Nil)
	f.projectDefault()
	if f.scalar(`SELECT count(*) FROM iga_relationship WHERE workspace_id = $1 AND state = 'current' AND relationship_type = 'backed_by_directory'`, f.ws) != 1 {
		t.Fatal("collector silence ended the directory link")
	}

	f.projectLocalSnapshot(linux, col, []localFact{{ref: "alice", name: "alice", uid: 1000}})
	if f.scalar(`SELECT count(*) FROM iga_relationship
		WHERE workspace_id = $1 AND relationship_type = 'backed_by_directory' AND state = 'ended' AND ended_reason = 'not_seen' AND valid_to IS NOT NULL`, f.ws) != 1 {
		t.Fatal("an authoritative snapshot without the mapping left the link current")
	}
	if f.scalar(`SELECT count(*) FROM iga_identity_accounts
		WHERE workspace_id = $1 AND provider = 'linux' AND display_name = 'alice' AND lifecycle = 'active'`, f.ws) != 1 {
		t.Fatal("dropping the mapping retired the local account")
	}
}

func (f *a3) latestRun(integ uuid.UUID) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	f.scan(`SELECT id FROM iga_scan_runs WHERE workspace_id = $1 AND integration_id = $2 ORDER BY completed_at DESC LIMIT 1`,
		[]any{f.ws, integ}, &id)
	return id
}
