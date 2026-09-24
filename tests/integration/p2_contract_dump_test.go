package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TEMPORARY: dumps every route's JSON for review. Deleted before commit.
func TestP2ContractDump(t *testing.T) {
	dir := os.Getenv("CONTRACT_DUMP_DIR")
	if dir == "" {
		t.Skip("CONTRACT_DUMP_DIR unset")
	}
	f := contractLab(t)
	api := f.api
	u := func(ref string) string { return refUUID(t, ref).String() }
	var cloudIdentity uuid.UUID
	f.l.db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = 'arn:aws:iam::429418377036:role/SharedToolRole'`, f.l.ws).Scan(&cloudIdentity)
	var obs uuid.UUID
	f.l.db.Raw(`SELECT id FROM cloud_scan_run WHERE id = ?`, f.runA2.ID).Scan(&obs)
	paths := []string{
		"/capabilities", "/pipeline", "/coverage", "/coverage?account=" + accountB,
		"/workloads", "/workloads?facets=account,runtime_kind,classification,region&limit=1",
		"/workloads/" + u(f.lambda), "/workloads/" + u(f.orphan), "/workloads/" + u(f.orphan) + "/identities", "/workloads/" + u(f.ecs), "/workloads/" + u(f.agent),
		"/workloads/" + u(f.lambda) + "/identities", "/workloads/" + u(f.ecs) + "/identities",
		"/workloads/" + u(f.lambda) + "/resources", "/workloads/" + u(f.lambda) + "/changes",
		"/workloads/" + u(f.lambda) + "/changes?kind=coverage", "/workloads/" + u(f.lambda) + "/classification",
		"/identities?facets=account,kind", "/identities?lifecycle=retired",
		"/identities/" + u(f.shared), "/identities/" + u(f.priya), "/identities/" + u(f.ops), "/identities/" + u(f.temp),
		"/identities/" + u(f.shared) + "/used-by", "/identities/" + u(f.ops) + "/used-by", "/identities/" + u(f.cross) + "/used-by",
		"/identities/" + u(f.shared) + "/permissions", "/identities/" + u(f.priya) + "/permissions", "/identities/" + u(f.ops) + "/permissions",
		"/identities/" + u(f.shared) + "/changes",
		"/external-principals/" + u(f.oidc), "/external-principals/" + u(f.rootC),
		"/external-principals/" + u(f.oidc) + "/referenced-by",
		"/resources?facets=kind,service,account",
		"/resources/" + u(f.tickets), "/resources/" + u(f.bucket), "/resources/" + u(f.keyC), "/resources/" + u(f.keyB),
		"/resources/" + u(f.tickets) + "/access", "/resources/" + u(f.tickets) + "/changes",
		"/graph" + qs("root", f.lambda, "direction", "forward"),
		"/graph" + qs("root", f.tickets, "direction", "reverse"),
		"/graph/expand" + qs("node", f.shared, "edge", "can_assume", "direction", "forward"),
		"/graph/path" + qs("from", f.lambda, "to", f.tickets),
		"/evidence" + qs("claim", f.grantReadTickets),
		"/evidence" + qs("claim", f.executesLambda),
		"/evidence" + qs("claim", f.crossEdge),
		"/evidence" + qs("claim", f.lambda),
		"/evidence" + qs("claim", f.oidc),
		"/evidence" + qs("claim", "coverage:"+f.runB.ID.String()+":iam_groups"),
		"/evidence" + qs("claim", f.grantReadTickets, "claim", f.grantToolbox),
		"/lookup" + qs("cloud_ref", "cloud_identity:"+cloudIdentity.String()),
		"/workloads?sort=bogus", "/workloads/" + uuid.NewString(), "/workloads?rev=1",
		"/graph" + qs("root", f.lambda, "direction", "forward", "assume_hops", "4"),
		"/evidence" + qs("claim", evidenceGrant(t, f.l, "ops", "OpsRead", "ReadOps")),
		"/evidence" + qs("claim", evidenceGrant(t, f.l, "priya", "PriyaOwn", "OwnRead")),
		"/evidence" + qs("claim", evidenceGrant(t, f.l, "SharedToolRole", "FinanceAll", "AllButFinance")),
		"/evidence" + qs("claim", evidenceGrant(t, f.l, "SharedToolRole", "ExternalKey", "Decrypt")),
		"/graph" + qs("root", f.priya, "direction", "forward"),
		"/workloads?cursor=garbage", "/identities/" + u(f.lambda), "/workloads/workload:" + u(f.lambda),
		"/resources/" + u(f.finance), "/external-principals/" + u(f.rootC) + "/referenced-by",
		"/lookup" + qs("cloud_ref", "cloud_workload:"+uuid.NewString()),
	}
	var ci []uuid.UUID
	f.l.db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND name = 'SharedToolRole'`, f.l.ws).Scan(&ci)
	if len(ci) == 1 {
		paths = append(paths, "/lookup"+qs("cloud_ref", "cloud_identity:"+ci[0].String()))
	}
	var cw []uuid.UUID
	f.l.db.Raw(`SELECT id FROM cloud_workload WHERE workspace_id = ? AND name = 'ticket-tools'`, f.l.ws).Scan(&cw)
	if len(cw) == 1 {
		paths = append(paths, "/lookup"+qs("cloud_ref", "cloud_workload:"+cw[0].String()))
	}
	_ = obs
	var out, dump strings.Builder
	for _, p := range paths {
		code, body := api.get(p)
		raw, _ := json.MarshalIndent(body, "", "  ")
		out.WriteString("=== GET " + p + " -> " + itoaContract(code) + "\n" + string(raw) + "\n\n")
	}
	// POSTs: a replay, a conflict, a provider-native refusal.
	f.api.withClaims(classClaims(f.user, f.member))
	opID := uuid.NewString()
	body := map[string]any{"operation_id": opID, "decision": "unclassified", "reason": "not an agent", "expected_version": 1}
	for _, b := range []map[string]any{body, body,
		{"operation_id": uuid.NewString(), "decision": "classified_agent", "reason": "x", "expected_version": 0},
	} {
		code, resp := api.do("POST", "/workloads/"+u(f.lambda)+"/classification", b)
		raw, _ := json.MarshalIndent(resp, "", "  ")
		dump.WriteString("=== POST classification -> " + itoaContract(code) + "\n" + string(raw) + "\n\n")
	}
	code, resp := api.do("POST", "/workloads/"+u(f.agent)+"/classification", map[string]any{"operation_id": uuid.NewString(), "decision": "classified_agent", "reason": "x", "expected_version": 0})
	raw, _ := json.MarshalIndent(resp, "", "  ")
	dump.WriteString("=== POST classification provider-native -> " + itoaContract(code) + "\n" + string(raw) + "\n\n")
	f.api.withClaims(map[string]string{})
	out.WriteString(dump.String())
	if err := os.WriteFile(filepath.Join(dir, "contract_dump.txt"), []byte(out.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
