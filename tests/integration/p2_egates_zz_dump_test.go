package integration

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// SCRATCH: dumps responses of the §7.1 lab for study. Deleted before commit.
func TestEgatesZZDump(t *testing.T) {
	out := os.Getenv("EGATES_DUMP")
	if out == "" {
		t.Skip("EGATES_DUMP unset")
	}
	l := newP2Lab(t, "egates-dump", true)
	a := egatesProduction(t, l)
	a.attach(egatesSharedRole, a.managed("FinanceAll", evidenceDoc(
		`{"Sid":"AllButFinance","Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::finance/*"}`)))
	b := egatesSandbox(t, l)
	egatesCycle(l, a)
	egatesCycle(l, b)
	api := l.api()
	var sb strings.Builder
	dump := func(path string) map[string]any {
		code, body := api.get(path)
		raw, _ := json.MarshalIndent(body, "", "  ")
		sb.WriteString("===== " + path + " -> " + itoa(code) + "\n" + string(raw) + "\n")
		return body
	}
	dump("/pipeline")
	dump("/coverage")
	dump("/workloads?facets=account,runtime_kind,region,classification")
	dump("/workloads?q=ticket&facets=account")
	wA := egatesWorkload(t, l, "ticket-tools", accountA)
	dump(egatesRoute(t, wA))
	dump(egatesRoute(t, wA, "/identities"))
	dump(egatesRoute(t, wA, "/resources"))
	dump(egatesRoute(t, wA, "/changes"))
	role := egatesIdentity(t, l, egatesSharedRole)
	dump(egatesRoute(t, role))
	dump(egatesRoute(t, role, "/used-by"))
	dump(egatesRoute(t, role, "/permissions"))
	res := egatesResource(t, l, egatesTickets)
	dump(egatesRoute(t, res))
	dump(egatesRoute(t, res, "/access"))
	dump("/graph" + qs("root", wA, "direction", "forward"))
	dump("/identities?facets=account,kind")
	dump("/resources?facets=kind,account,service")
	loopA := egatesIdentity(t, l, "loop-a")
	dump("/graph" + qs("root", loopA, "direction", "forward"))
	dump("/graph/path" + qs("from", wA, "to", res))
	dump(egatesRoute(t, egatesIdentity(t, l, "partner-access"), "/used-by"))
	dump("/evidence" + qs("claim", evidenceGrant(t, l, egatesSharedRole, egatesTicketRead, "ReadTickets")))
	dump("/evidence" + qs("claim", evidenceGrant(t, l, egatesSharedRole, egatesToolbox, "")))
	dump("/evidence" + qs("claim", evidenceGrant(t, l, egatesSharedRole, "FinanceAll", "AllButFinance")))
	dump("/evidence" + qs("claim", evidenceGrant(t, l, "ops", "OpsRead", "ReadOps")))
	dump("/evidence" + qs("claim", evidenceTarget(t, l, egatesTicketRead, "ReadTickets", egatesTickets)))
	dump("/evidence" + qs("claim", res))
	dump("/evidence" + qs("claim", evidenceGrant(t, l, egatesSharedRole, egatesTicketRead, "ReadTickets"), "include", "raw"))
	fin := egatesResource(t, l, "arn:aws:s3:::finance/*")
	dump(egatesRoute(t, fin))
	dump(egatesRoute(t, fin, "/access"))
	dump("/graph/path" + qs("from", wA, "to", fin))
	os.WriteFile(out, []byte(sb.String()), 0o644)
}

func itoa(n int) string { return graphItoa(int64(n)) }
