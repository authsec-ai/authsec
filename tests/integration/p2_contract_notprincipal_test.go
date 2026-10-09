package integration

// D-44 on the canvas: "every path into a role with trust_has_not_principal
// carries not_principal_unresolved" (SPEC-iga-phase2-graph.md §5.3 vocabulary
// "The trust policy uses NotPrincipal"; §5.4 "never states a completeness it
// did not establish").
//
// A NotPrincipal statement ("everyone except X") names no one, so it yields no
// can_assume edge (D-44), and /evidence puts the code only on the role's
// can_assume claims. A workload reaches the role through executes_as, and the
// role reaches a resource through grant and target: none of those claims
// carries it. So on the path a workload's canvas draws, the ROLE NODE's
// limitation (traverse_limits.go graphRestrictionLimitations, over the flag
// fetchIdentities reads) is the only thing saying who may assume the role
// could not be resolved. Without it the path would read as fully known.
//
// Built over the REAL worker and projector: the trust documents are the fake
// IAM's, the flag is the projector's.

import (
	"net/http"
	"testing"
)

// contractNotPrincipal is the one limitation D-44 adds: the code alone, the
// same object /evidence renders for a can_assume into the role (D-98).
var contractNotPrincipal = map[string]any{"code": "not_principal_unresolved"}

func TestP2ContractGraphNotPrincipalUnresolved(t *testing.T) {
	l := newP2Lab(t, "p2-contract-notprincipal", true)
	a := l.account(accountA)
	// GuardedRole: Lambda may assume it, and a Deny with NotPrincipal refuses
	// everyone but the partner -- the usual guard-rail shape. PlainRole: the
	// same, without the guard. Both hold the same grant, so the only
	// difference between their paths is the NotPrincipal statement.
	guarded := trustRole(a, "GuardedRole", "AROAGUARDEDROLEGUAR1", trustDoc(
		trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole"),
		`{"Sid":"OnlyPartner","Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::`+contractAccountC+`:root"},"Action":"sts:AssumeRole"}`))
	plain := trustRole(a, "PlainRole", "AROAPLAINROLEPLAIN01", trustDoc(
		trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole")))
	listsFunctions(a, "us-east-1", "guarded-fn", guarded, "plain-fn", plain)
	report := contractManaged(a, "ReportRead", contractDoc(
		`{"Sid":"GetReport","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/q3.csv"}`))
	a.attach("GuardedRole", report)
	a.attach("PlainRole", report)
	l.scanAndProject(a)
	api := l.api()

	guardedFn := evidenceNode(t, l, "workload", "iga_workload", "guarded-fn")
	plainFn := evidenceNode(t, l, "workload", "iga_workload", "plain-fn")
	guardedRole := evidenceNode(t, l, "identity", "iga_identity_accounts", "GuardedRole")
	plainRole := evidenceNode(t, l, "identity", "iga_identity_accounts", "PlainRole")
	resource := evidenceNode(t, l, "resource", "iga_resources", "arn:aws:s3:::reports/q3.csv")

	// The fixture: the projector flagged GuardedRole and not PlainRole, and
	// /evidence states the code, with these fields, on the can_assume into it.
	for ref, want := range map[string]bool{guardedRole: true, plainRole: false} {
		code, body := api.get("/identities/" + refUUID(t, ref).String())
		mustStatus(t, "identity detail", code, body, http.StatusOK)
		if dig(body, "data", "provider_attrs", "trust_has_not_principal") != want {
			t.Fatalf("fixture: %s provider_attrs = %s, want trust_has_not_principal %v",
				ref, contractJSON(dig(body, "data", "provider_attrs")), want)
		}
	}
	assume := evidenceRelationship(t, l, "can_assume", "lambda.amazonaws.com", "GuardedRole")
	if got := evidenceLim(evidenceGet(t, api, assume), "not_principal_unresolved"); contractCanonical(got) != contractCanonical(contractNotPrincipal) {
		t.Fatalf("fixture: /evidence of the can_assume into GuardedRole carries %v, want %v", got, contractNotPrincipal)
	}

	// carries: the element's limitations hold D-44's code, exactly as
	// /evidence renders it; lacks: they do not hold it at all.
	carries := func(ls []any) bool { return contractHas(ls, contractNotPrincipal) }
	lacks := func(ls []any) bool { return !graphHasCode(ls, "not_principal_unresolved") }
	nodeOf := func(body map[string]any, ref string, path ...any) map[string]any {
		for _, n := range digl(body, append(path, "nodes")...) {
			if digs(n, "ref") == ref {
				return n.(map[string]any)
			}
		}
		return nil
	}

	// Every graph route: the role node carries it wherever it appears -- as a
	// root, reached forward from its workload, reached in reverse from the
	// resource, and in an expansion -- and PlainRole never does.
	for _, c := range []struct {
		name, path string
		want       map[string]bool // node -> carries the code
	}{
		{"the role as root", "/graph" + qs("root", guardedRole, "direction", "forward"),
			map[string]bool{guardedRole: true}},
		{"forward from its workload", "/graph" + qs("root", guardedFn, "direction", "forward"),
			map[string]bool{guardedRole: true}},
		{"forward from the control workload", "/graph" + qs("root", plainFn, "direction", "forward"),
			map[string]bool{plainRole: false}},
		{"reverse from the resource", "/graph" + qs("root", resource, "direction", "reverse"),
			map[string]bool{guardedRole: true, plainRole: false}},
		{"expanding the workload's executes_as", "/graph/expand" + qs("node", guardedFn, "edge", "executes_as", "direction", "forward"),
			map[string]bool{guardedRole: true}},
	} {
		code, body := api.get(c.path)
		mustStatus(t, c.name, code, body, http.StatusOK)
		for ref, want := range c.want {
			n := nodeOf(body, ref, "data")
			switch {
			case n == nil:
				t.Errorf("%s: %s is not in the response", c.name, ref)
			case want && !carries(digl(n, "limitations")):
				t.Errorf("%s: the NotPrincipal role %s carries %s, want %v (D-44)", c.name, ref,
					contractCanonical(digl(n, "limitations")), contractNotPrincipal)
			case !want && !lacks(digl(n, "limitations")):
				t.Errorf("%s: %s, whose trust has no NotPrincipal, carries it: %s (§2.14.7 never generic)", c.name, ref,
					contractCanonical(digl(n, "limitations")))
			}
		}
	}

	// /graph/path: every path into the NotPrincipal role carries the code in
	// its own limitations (the union of its steps'), through the role node;
	// the control's path, identical but for the guard, does not.
	for _, c := range []struct {
		name, from, role string
		want             bool
	}{
		{"into the NotPrincipal role", guardedFn, guardedRole, true},
		{"into the control role", plainFn, plainRole, false},
	} {
		code, body := api.get("/graph/path" + qs("from", c.from, "to", resource))
		mustStatus(t, "/graph/path "+c.name, code, body, http.StatusOK)
		paths := digl(body, "data", "paths")
		if digs(body, "data", "outcome") != "found" || len(paths) == 0 {
			t.Fatalf("path %s = %s, want found", c.name, contractJSON(body["data"]))
		}
		for i := range paths {
			n := nodeOf(body, c.role, "data", "paths", i)
			if n == nil {
				t.Fatalf("path %s %d does not pass %s: %s", c.name, i, c.role, contractJSON(paths[i]))
			}
			pl := digl(body, "data", "paths", i, "limitations")
			if c.want && (!carries(pl) || !carries(digl(n, "limitations"))) {
				t.Errorf("path %s %d: limitations %s, role node %s -- want %v on both (D-44)", c.name, i,
					contractCanonical(pl), contractCanonical(digl(n, "limitations")), contractNotPrincipal)
			}
			if !c.want && !lacks(pl) {
				t.Errorf("path %s %d carries not_principal_unresolved, which does not apply: %s", c.name, i, contractCanonical(pl))
			}
		}
	}
}
