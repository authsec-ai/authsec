package integration

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/directory/adresolve"
	"github.com/google/uuid"
)

// TestTRD2ITA5CDerivedDirectoryBacking reads an A9-derived backed_by_directory
// edge through the v2 graph and identity readers. The relationship is produced
// by the resolver, not inserted by hand.
func TestTRD2ITA5CDerivedDirectoryBacking(t *testing.T) {
	f := newA3(t)
	api := newA5HTTP(t, f.g, f.ws)
	f.seedDirectoryInstance(a9Forest, a9Domain, a9Forest)
	ad, adCol, _ := f.seedCollector("ad")
	f.projectAD(ad, adCol, a9User, a9UserSID, "alice", "CN=alice,DC=authsec,DC=test", "ad_user", true)
	linux, col, _ := f.seedCollector("linux")
	f.projectLocalSnapshot(linux, col, []localFact{{
		ref: "alice", name: "alice", uid: 1000,
		native: map[string]any{
			"directory_guid": a9User, "directory_sid": a9UserSID,
			"directory_domain": a9Forest, "mapping_source": "sssd",
		},
	}})

	if f.scalar(`SELECT count(*) FROM iga_relationship
		WHERE workspace_id = $1 AND relationship_type = 'backed_by_directory' AND state = 'current'
		  AND basis = 'derived' AND derivation_rule = $2`, f.ws, adresolve.Rule("sssd")) != 1 {
		t.Fatal("sssd user link missing")
	}
	var localID, adID uuid.UUID
	var localState, adState string
	f.scan(`SELECT id, account_state FROM iga_identity_accounts
		WHERE workspace_id = $1 AND provider = 'linux' AND account_kind = 'local_user'`,
		[]any{f.ws}, &localID, &localState)
	f.scan(`SELECT id, account_state FROM iga_identity_accounts
		WHERE workspace_id = $1 AND provider = 'ad' AND account_kind = 'ad_user'`,
		[]any{f.ws}, &adID, &adState)
	if localID == adID {
		t.Fatal("local and AD identities were merged")
	}
	if localState != "enabled" {
		t.Fatalf("local account_state = %s, want enabled", localState)
	}
	if adState != "disabled" {
		t.Fatalf("AD writer account_state = %s, want disabled (account_disabled was set)", adState)
	}

	code, raw, body := api.get("/graph?root=identity:" + localID.String() + "&direction=forward&graph=v2")
	if code != http.StatusOK {
		t.Fatalf("v2 graph = %d %s", code, raw)
	}
	if strings.Contains(strings.ToLower(string(raw)), "kerberos") {
		t.Fatalf("graph used kerberos wording: %s", raw)
	}
	edges, _ := dig(body, "data", "edges").([]any)
	backing := 0
	for _, item := range edges {
		edge, _ := item.(map[string]any)
		kind, _ := edge["kind"].(string)
		meaning, _ := edge["meaning"].(string)
		mechanism, _ := edge["mechanism"].(string)
		for _, word := range []string{kind, meaning, mechanism} {
			low := strings.ToLower(word)
			if strings.Contains(low, "kerberos") || strings.Contains(low, "uses") {
				t.Fatalf("edge wording %q in %+v", word, edge)
			}
		}
		if meaning != "directory_backing" {
			continue
		}
		backing++
		if edge["basis"] != "derived" {
			t.Fatalf("directory edge basis = %v, want derived (reader exposes basis)", edge["basis"])
		}
		to, _ := edge["to"].(string)
		if !strings.Contains(to, adID.String()) {
			t.Fatalf("directory edge to = %s, want the ad identity", to)
		}
	}
	if backing != 1 {
		t.Fatalf("directory_backing edges = %d\n%s", backing, raw)
	}
	nodes, _ := dig(body, "data", "nodes").([]any)
	seen := map[string]bool{}
	for _, item := range nodes {
		node, _ := item.(map[string]any)
		ref, _ := node["ref"].(string)
		if strings.Contains(ref, localID.String()) || strings.Contains(ref, adID.String()) {
			seen[ref] = true
		}
	}
	if len(seen) != 2 {
		t.Fatalf("identity nodes = %v, want the local and AD identities kept apart", seen)
	}

	a5cIdentityRow(t, api, "local_user", localID, "enabled")
	a5cIdentityRow(t, api, "ad_user", adID, "disabled")

	code, raw, body = api.get("/identities?graph=v2&provider=linux&kind=ad_user")
	if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" ||
		!strings.Contains(string(raw), "does not admit account kind ad_user") {
		t.Fatalf("incompatible kind = %d %s", code, raw)
	}

	code, raw, body = api.get("/identities")
	if code != http.StatusOK || strings.Contains(string(raw), localID.String()) ||
		strings.Contains(string(raw), adID.String()) || strings.Contains(string(raw), "account_state") {
		t.Fatalf("default identities leaked v2 rows: %d %s", code, raw)
	}
	code, raw, body = api.get("/identities?kind=local_user")
	if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" ||
		digs(body, "error", "message") != "kind must be one of iam_role, iam_user, iam_group" ||
		digs(body, "error", "parameter") != "kind" {
		t.Fatalf("default kind=local_user = %d %s", code, raw)
	}
	code, raw, _ = api.get("/graph?root=identity:" + localID.String() + "&direction=forward")
	if strings.Contains(string(raw), "directory_backing") || strings.Contains(string(raw), adID.String()) {
		t.Fatalf("default graph showed the derived edge: %d %s", code, raw)
	}
}

// TestTRD2ITA5CNonAWSIdentityTabs reads one local user, one Kubernetes
// service account and one AD user through every identity tab under graph=v2.
func TestTRD2ITA5CNonAWSIdentityTabs(t *testing.T) {
	f := newA3(t)
	api := newA5HTTP(t, f.g, f.ws)

	linux, lcol, _ := f.seedCollector("linux")
	f.projectLocalSnapshot(linux, lcol, []localFact{{ref: "svc", name: "svc-invoice", uid: 995}})

	k8s, kcol, _ := f.seedCollector("kubernetes")
	krun := f.seedRun(k8s, "runtime_batch", false)
	f.seedFact(k8s, krun, "k8s.service_account", "sa", "sa",
		map[string]any{"native": map[string]any{"namespace": "pay", "name": "invoice", "uid": "sa-uid-1"}}, nil)
	f.seedBatch(k8s, kcol, uuid.New(), krun, 1, uuid.Nil)
	f.projectDefault()

	f.seedDirectoryInstance(a9Forest, a9Domain, a9Forest)
	ad, acol, _ := f.seedCollector("ad")
	f.projectAD(ad, acol, a9User, a9UserSID, "ada", "CN=ada,DC=authsec,DC=test", "ad_user", false)

	var ids []uuid.UUID
	for _, provider := range []string{"linux", "kubernetes", "ad"} {
		var id uuid.UUID
		f.scan(`SELECT id FROM iga_identity_accounts
			WHERE workspace_id = $1 AND provider = $2
			  AND account_kind IN ('local_user', 'k8s_service_account', 'ad_user')
			LIMIT 1`, []any{f.ws, provider}, &id)
		ids = append(ids, id)
	}
	tabs := []string{"", "/used-by", "/permissions", "/changes", "/observed-use"}
	for _, id := range ids {
		for _, tab := range tabs {
			path := "/identities/" + id.String() + tab + "?graph=v2"
			code, raw, body := api.get(path)
			if code != http.StatusOK {
				t.Fatalf("%s = %d %s", path, code, raw)
			}
			a5cNoAWSWording(t, path, raw)
			if tab == "" {
				if digs(body, "data", "account_state") == "" {
					t.Fatalf("%s omitted account_state: %s", path, raw)
				}
				if digs(body, "data", "region") != "global" {
					t.Fatalf("%s region = %s", path, raw)
				}
				if _, ok := dig(body, "data", "arn").(string); !ok || digs(body, "data", "arn") != "" {
					t.Fatalf("%s arn = %#v, want the empty native segment NativeOfKey returns for a non-aws key", path, dig(body, "data", "arn"))
				}
				if dig(body, "data", "account") != nil {
					t.Fatalf("%s invented an account: %s", path, raw)
				}
			}
			if tab == "/permissions" || tab == "/used-by" {
				lims, _ := dig(body, "data", "limitations").([]any)
				if len(lims) != 1 || lims[0] != "not_applicable" {
					t.Fatalf("%s limitations = %v", path, dig(body, "data", "limitations"))
				}
			}
		}
		code, raw, _ := api.get("/identities/" + id.String())
		if code != http.StatusNotFound {
			t.Fatalf("default detail returned a non-AWS identity: %d %s", code, raw)
		}
	}
}

func a5cIdentityRow(t *testing.T, api *a5HTTP, kind string, id uuid.UUID, state string) {
	t.Helper()
	code, raw, body := api.get("/identities?graph=v2&kind=" + kind)
	if code != http.StatusOK {
		t.Fatalf("kind=%s = %d %s", kind, code, raw)
	}
	rows, _ := dig(body, "data").([]any)
	var found map[string]any
	for _, item := range rows {
		row, _ := item.(map[string]any)
		ref, _ := row["ref"].(string)
		if strings.Contains(ref, id.String()) {
			found = row
			break
		}
	}
	if found == nil {
		t.Fatalf("kind=%s did not return %s\n%s", kind, id, raw)
	}
	if found["kind"] != kind || found["account_state"] != state || found["region"] != "global" {
		t.Fatalf("kind=%s row = %+v", kind, found)
	}
	if found["lifecycle"] == "" || found["state"] == "" {
		t.Fatalf("kind=%s dropped lifecycle or state: %+v", kind, found)
	}
}

func a5cNoAWSWording(t *testing.T, path string, raw []byte) {
	t.Helper()
	low := strings.ToLower(string(raw))
	for _, bad := range []string{"access advisor", "kerberos", "iam:generate", "this role's", "this user's access keys"} {
		if strings.Contains(low, bad) {
			t.Fatalf("%s contains %q: %s", path, bad, raw)
		}
	}
}
