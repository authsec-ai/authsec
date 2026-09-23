package integration

// T6.8 -- GET /lookup (§5.3 Lookup, E16): a Cloud Inventory row opens the
// graph object projected from it, by source key through the row's own
// connector, and never by name.

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
)

// listsCloudRow is the id of a Cloud Inventory row of one connector, by name.
func listsCloudRow(t *testing.T, l *p2Lab, table string, conn uuid.UUID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(`SELECT id FROM `+table+` WHERE workspace_id = ? AND connector_id = ? AND name = ?`,
		l.ws, conn, name).Row().Scan(&id); err != nil {
		t.Fatalf("no %s row %q for connector %s: %v", table, name, conn, err)
	}
	return id
}

// listsLiveNode is the live graph node with this ARN.
func listsLiveNode(t *testing.T, l *p2Lab, table, arn string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(`SELECT id FROM `+table+` WHERE workspace_id = ? AND source_key = 'aws' || chr(31) || ?
	          AND lifecycle = 'active'`, l.ws, arn).Row().Scan(&id); err != nil {
		t.Fatalf("no live %s for %s: %v", table, arn, err)
	}
	return id
}

func TestP2ListsLookupByKeyNeverByName(t *testing.T) {
	l := newP2Lab(t, "p2-lists-lookup", true)
	a := l.account(accountA)
	b := l.account(accountB)
	// The SAME role name and the SAME function name in two accounts: a lookup
	// by name could not tell them apart.
	for _, acct := range []*p2Account{a, b} {
		role := acct.role("SharedToolRole", "AROASHARED"+acct.id[:10])
		listsFunctions(acct, "us-east-1", "ticket-tools", role)
	}
	l.scanAndProject(a)
	l.scanAndProject(b)
	api := l.api()

	lookup := func(ref string) (int, map[string]any) { return api.get("/lookup" + qs("cloud_ref", ref)) }
	want := map[string]string{}
	for _, acct := range []*p2Account{a, b} {
		ci := listsCloudRow(t, l, "cloud_identity", acct.conn, "SharedToolRole")
		cw := listsCloudRow(t, l, "cloud_workload", acct.conn, "ticket-tools")
		identity := listsLiveNode(t, l, "iga_identity_accounts", acct.roleARN("SharedToolRole"))
		workload := listsLiveNode(t, l, "iga_workload", "arn:aws:lambda:us-east-1:"+acct.id+":function:ticket-tools")

		code, body := lookup("cloud_identity:" + ci.String())
		mustStatus(t, "lookup "+acct.id+" identity", code, body, 200)
		if digs(body, "data", "ref") != refOf("identity", identity) || digs(body, "data", "lifecycle") != "active" {
			t.Errorf("%s's SharedToolRole row -> %v, want identity:%s", acct.id, body["data"], identity)
		}
		if num(body, "meta", "rev") != 2 || digs(body, "meta", "graph_state") != "published" {
			t.Errorf("lookup meta = %v", body["meta"])
		}
		code, body = lookup("cloud_workload:" + cw.String())
		mustStatus(t, "lookup "+acct.id+" workload", code, body, 200)
		if digs(body, "data", "ref") != refOf("workload", workload) {
			t.Errorf("%s's ticket-tools row -> %v, want workload:%s", acct.id, body["data"], workload)
		}
		want[acct.id] = identity.String()
	}
	if want[accountA] == want[accountB] {
		t.Fatal("both accounts' SharedToolRole rows opened one graph object")
	}

	for name, ref := range map[string]string{
		"unknown row": "cloud_identity:" + uuid.NewString(),
	} {
		if code, body := lookup(ref); code != 404 || errCode(body) != "not_found" {
			t.Errorf("%s: %d %v, want 404 not_found", name, code, body)
		}
	}
	for name, path := range map[string]string{
		"missing":        "/lookup",
		"malformed id":   "/lookup" + qs("cloud_ref", "cloud_identity:not-a-uuid"),
		"a graph ref":    "/lookup" + qs("cloud_ref", "identity:"+uuid.NewString()),
		"extra param":    "/lookup" + qs("cloud_ref", "cloud_identity:"+uuid.NewString(), "name", "SharedToolRole"),
		"unknown type":   "/lookup" + qs("cloud_ref", "cloud_resource:"+uuid.NewString()),
		"no type at all": "/lookup" + qs("cloud_ref", uuid.NewString()),
	} {
		if code, body := api.get(path); code != 400 || errCode(body) != "invalid_parameter" {
			t.Errorf("%s: %d %v, want 400 invalid_parameter", name, code, body)
		}
	}

	// THROUGH THE ROW'S OWN CONNECTOR: a row naming a connector that does not
	// support the node with its key opens nothing.
	ciA := listsCloudRow(t, l, "cloud_identity", a.conn, "SharedToolRole")
	l.db.Exec(`UPDATE cloud_identity SET connector_id = ? WHERE id = ?`, b.conn, ciA)
	if code, body := lookup("cloud_identity:" + ciA.String()); code != 404 {
		t.Errorf("A's row re-pointed at B's connector -> %d %v, want 404: B does not support A's role", code, body)
	}
	l.db.Exec(`UPDATE cloud_identity SET connector_id = ? WHERE id = ?`, a.conn, ciA)
	cwA := listsCloudRow(t, l, "cloud_workload", a.conn, "ticket-tools")
	l.db.Exec(`UPDATE cloud_workload SET connector_id = ? WHERE id = ?`, b.conn, cwA)
	if code, body := lookup("cloud_workload:" + cwA.String()); code != 404 {
		t.Errorf("A's workload row re-pointed at B's connector -> %d %v, want 404: B does not support A's function", code, body)
	}
	l.db.Exec(`UPDATE cloud_workload SET connector_id = ? WHERE id = ?`, a.conn, cwA)

	// RECREATED, NOT YET PROJECTED: the scan has collected the new principal
	// (a new RoleId under the same ARN) but the graph still holds the old one.
	// The row must not open the old principal.
	oldRef := "identity:" + want[accountA]
	a.role("SharedToolRole", "AROASHAREDRECREATED1")
	l.scan(a, "scan-worker-lookup-recreated")
	var uid string
	l.db.Raw(`SELECT attrs->>'unique_id' FROM cloud_identity WHERE id = ?`, ciA).Scan(&uid)
	if uid != "AROASHAREDRECREATED1" {
		t.Fatalf("setup: the inventory row's unique id is %q after the rescan", uid)
	}
	if code, body := lookup("cloud_identity:" + ciA.String()); code != 404 {
		t.Errorf("recreated, not yet projected -> %d %v, want 404 (never the old principal %s)", code, body, oldRef)
	}
	l.project("projector-lookup-recreated")
	code, body := lookup("cloud_identity:" + ciA.String())
	mustStatus(t, "lookup after the recreation is projected", code, body, 200)
	if got := digs(body, "data", "ref"); got == oldRef ||
		got != refOf("identity", listsLiveNode(t, l, "iga_identity_accounts", a.roleARN("SharedToolRole"))) {
		t.Errorf("after projection -> %s, want the NEW live identity (old was %s)", got, oldRef)
	}
}

// D-4: before the first publication no graph object exists, so a lookup is
// 404 -- never an error, never a stale guess.
func TestP2ListsLookupBeforeFirstPublication(t *testing.T) {
	l := newP2Lab(t, "p2-lists-lookup-unpublished", true)
	a := oneLambda(l)
	l.scan(a, "scan-worker-lookup-unpublished") // collected, not projected
	ci := listsCloudRow(t, l, "cloud_identity", a.conn, "refund-lambda-role")
	if code, body := l.api().get("/lookup" + qs("cloud_ref", "cloud_identity:"+ci.String())); code != 404 || errCode(body) != "not_found" {
		t.Errorf("lookup before any publication = %d %v, want 404", code, body)
	}
	l.project("projector-lookup-unpublished")
}

// Names repeat INSIDE one account too, and there only the source key tells
// the objects apart: a function name in two regions (same connector, no
// creation-boundary id on a workload row), and a role and a user sharing a
// name. The identity rows' unique ids are removed, as for a row collected
// without one (D-81 matches the immutable key only "when the row has one"),
// so nothing but the key can separate them. And /lookup is revision-bound
// (D-82): a stale rev is 409.
func TestP2ListsLookupSameNameInOneAccount(t *testing.T) {
	l := newP2Lab(t, "p2-lists-lookup-names", true)
	a := l.account(accountA, "us-east-1", "eu-west-1")
	role := a.role("deployer", "AROADEPLOYERDEPLOYE1")
	a.iam.users = append(a.iam.users, iamtypes.User{
		Arn: aws.String("arn:aws:iam::" + accountA + ":user/deployer"), UserName: aws.String("deployer"),
		UserId: aws.String("AIDADEPLOYERDEPLOYE1"), Path: aws.String("/"), CreateDate: ago(0),
	})
	listsFunctions(a, "us-east-1", "ticket-tools", role)
	listsFunctions(a, "eu-west-1", "ticket-tools", role)
	l.scanAndProject(a)
	if err := l.db.Exec(`UPDATE cloud_identity SET attrs = attrs - 'unique_id' WHERE workspace_id = ? AND name = 'deployer'`,
		l.ws).Error; err != nil {
		t.Fatalf("drop unique ids: %v", err)
	}
	api := l.api()

	for table, typ := range map[string]string{"cloud_workload": "workload", "cloud_identity": "identity"} {
		var rows []struct {
			ID       uuid.UUID
			NativeID string
		}
		l.db.Raw(`SELECT id, native_id FROM `+table+` WHERE workspace_id = ? AND name IN ('ticket-tools', 'deployer')`,
			l.ws).Scan(&rows)
		if len(rows) != 2 {
			t.Fatalf("setup: %d %s rows share the name, want 2", len(rows), table)
		}
		got := map[string]bool{}
		for _, r := range rows {
			node := "iga_identity_accounts"
			if typ == "workload" {
				node = "iga_workload"
			}
			want := refOf(typ, listsLiveNode(t, l, node, r.NativeID))
			code, body := api.get("/lookup" + qs("cloud_ref", table+":"+r.ID.String()))
			mustStatus(t, "lookup "+r.NativeID, code, body, 200)
			if ref := digs(body, "data", "ref"); ref != want {
				t.Errorf("%s row %s -> %s, want %s (the object with ITS key)", table, r.NativeID, ref, want)
			}
			got[digs(body, "data", "ref")] = true
		}
		if len(got) != 2 {
			t.Errorf("the two %s rows sharing a name opened %d object(s), want 2", table, len(got))
		}
	}

	var ci uuid.UUID
	l.db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND name = 'deployer' LIMIT 1`, l.ws).Scan(&ci)
	l.scanAndProject(a) // rev 2
	if code, body := api.get("/lookup" + qs("cloud_ref", "cloud_identity:"+ci.String(), "rev", "1")); code != 409 || errCode(body) != "revision_stale" {
		t.Errorf("lookup at a stale rev = %d %v, want 409 revision_stale", code, body)
	}
}
