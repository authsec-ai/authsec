package integration

// GET /external-principals/:id and .../referenced-by (§5.3, T6.3; D-42,
// D-47, D-87, D-88; E11): an unconnected account, a service principal, OIDC
// subjects (a pattern and an exact one) and "*" -- each saying which account
// it belongs to and WHY it is unresolved -- a principal a later connection
// resolves, and the can_assume edges from each, one row per declaring
// statement.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// idetailExternalLab builds account A's trusting roles through the real
// pipeline.
func idetailExternalLab(t *testing.T, name string) (*p2Lab, *p2Account) {
	l := newP2Lab(t, name, true)
	a := l.account(accountA)
	cRoot := `{"AWS":"arn:aws:iam::` + trustAccountC + `:root"}`
	// Two statements naming C's root under different conditions: two edges.
	trustRole(a, "partner-access", "AROAPARTNERACCESS001", trustDoc(
		trustAllow(`{"AWS":"arn:aws:iam::`+trustAccountC+`:role/partner-role"}`, "sts:AssumeRole"),
		`{"Sid":"PartnerA","Effect":"Allow","Principal":`+cRoot+`,"Action":"sts:AssumeRole",`+
			`"Condition":{"StringEquals":{"sts:ExternalId":"alpha"}}}`,
		`{"Sid":"PartnerB","Effect":"Allow","Principal":`+cRoot+`,"Action":"sts:AssumeRole",`+
			`"Condition":{"StringEquals":{"sts:ExternalId":"beta"}}}`))
	// NotAction: its edge carries negated (D-88).
	trustRole(a, "negated-role", "AROANEGATEDROLE00001", trustDoc(
		`{"Effect":"Allow","Principal":`+cRoot+`,"NotAction":"sts:TagSession"}`))
	trustRole(a, "gha-deploy", "AROAGHADEPLOYGHADEPL", trustDoc(
		`{"Effect":"Allow","Principal":{"Federated":"`+trustGitHubProvider+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:authsec-ai/authsec:*"}}}`))
	trustRole(a, "gha-main", "AROAGHAMAINGHAMAINGH", trustDoc(
		`{"Effect":"Allow","Principal":{"Federated":"`+trustGitHubProvider+`"},"Action":"sts:AssumeRoleWithWebIdentity",`+
			`"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:authsec-ai/authsec:ref:refs/heads/main"}}}`))
	trustRole(a, "open-role", "AROAOPENROLEOPENROLE", trustDoc(trustAllow(`"*"`, "sts:AssumeRole")))
	// The lab's own Lambda trust: an aws_service principal.
	a.role("lambda-runner", "AROALAMBDARUNNER0001")
	trustCycle(l, a, nil)
	return l, a
}

func TestP2IdetailExternalPrincipals(t *testing.T) {
	l, _ := idetailExternalLab(t, "p2-idetail-external")
	api := l.api()
	detail := func(issuer, subject string) map[string]any {
		t.Helper()
		body := idetailGet(t, api, "/external-principals/"+idetailExternalID(t, l, issuer, subject).String())
		if digs(body, "meta", "graph_state") != "published" || digl(body, "meta", "coverage") == nil {
			t.Errorf("meta = %s, want the detail envelope with coverage", idetailJSON(body["meta"]))
		}
		return dig(body, "data").(map[string]any)
	}

	// E11: account C, not connected -- which account, and why unresolved.
	root := detail("aws", trustAccountC)
	if root["mechanism"] != models.ExternalPrincipalAWSAccount || root["issuer"] != "aws" || root["subject"] != trustAccountC ||
		root["name"] != trustAccountC || digs(root, "account", "id") != trustAccountC ||
		dig(root, "account", "connected") != false || root["account_connected"] != false || root["resolution"] != nil ||
		root["unresolved_reason"] != "account_not_connected" || root["lifecycle"] != "active" || root["state"] != "current" ||
		digs(root, "first_seen_at") == "" || digs(root, "last_seen_at") == "" || digs(root, "last_confirmed_at") == "" ||
		!strings.HasPrefix(digs(root, "ref"), "external_principal:") {
		t.Errorf("account C = %s, want aws_account %s, account not connected, resolution null, active/current", idetailJSON(root), trustAccountC)
	}
	// D-96d: every detail route states retired_reason, null while active.
	if v, has := root["retired_reason"]; !has || v != nil {
		t.Errorf("active principal retired_reason = %v (present %v), want null: only a retired one names a reason", v, has)
	}
	role := detail("aws", "arn:aws:iam::"+trustAccountC+":role/partner-role")
	if role["mechanism"] != models.ExternalPrincipalAWSPrincipal || digs(role, "account", "id") != trustAccountC ||
		role["unresolved_reason"] != "account_not_connected" {
		t.Errorf("C's role = %s, want an aws_principal in account C, account not connected", idetailJSON(role))
	}
	// A service principal names no account: account and account_connected
	// are null, never "an unconnected account".
	svc := detail("aws", "lambda.amazonaws.com")
	if svc["mechanism"] != models.ExternalPrincipalAWSService || svc["account"] != nil || svc["account_connected"] != nil ||
		svc["unresolved_reason"] != "service_principal" || svc["name"] != "lambda.amazonaws.com" {
		t.Errorf("service principal = %s, want aws_service, account null, account_connected null, service_principal", idetailJSON(svc))
	}
	// OIDC: issuer and subject verbatim; a pattern subject is a wildcard, an
	// exact one is simply not an identity we hold.
	gha := detail("token.actions.githubusercontent.com", "repo:authsec-ai/authsec:*")
	if gha["mechanism"] != models.ExternalPrincipalOIDC || gha["account"] != nil || gha["unresolved_reason"] != "wildcard" ||
		gha["name"] != "token.actions.githubusercontent.com · repo:authsec-ai/authsec:*" {
		t.Errorf("OIDC pattern = %s, want oidc, no account, wildcard, labelled issuer · subject", idetailJSON(gha))
	}
	main := detail("token.actions.githubusercontent.com", "repo:authsec-ai/authsec:ref:refs/heads/main")
	if main["unresolved_reason"] != "not_in_inventory" || main["mechanism"] != models.ExternalPrincipalOIDC {
		t.Errorf("OIDC exact subject = %s, want not_in_inventory", idetailJSON(main))
	}
	// "*": any AWS principal (D-42), no account, a wildcard.
	star := detail("aws", "*")
	if star["name"] != "any AWS principal" || star["account"] != nil || star["unresolved_reason"] != "wildcard" ||
		star["mechanism"] != models.ExternalPrincipalAWSAccount {
		t.Errorf(`"*" = %s, want "any AWS principal", no account, wildcard`, idetailJSON(star))
	}

	// referenced-by: the can_assume edges FROM C's root -- one row per
	// declaring statement, each with its own conditions -- by target name.
	cID := idetailExternalID(t, l, "aws", trustAccountC)
	body := idetailGet(t, api, "/external-principals/"+cID.String()+"/referenced-by")
	items := digl(body, "data")
	if got := fmt.Sprint(idetailNames(items, "target", "name")); got != "[negated-role partner-access partner-access]" {
		t.Fatalf("referenced-by = %v, want [negated-role partner-access partner-access]: %s", got, idetailJSON(items))
	}
	sids := map[string]string{}
	for _, it := range items {
		if digs(it, "type") != models.RelTypeCanAssume || digs(it, "mechanism") != models.MechanismSTSAssumeRole ||
			digs(it, "state") != "current" || digs(it, "valid_from") == "" || digs(it, "target", "kind") != models.CloudIdentityIAMRole ||
			digs(it, "target", "account", "id") != accountA || !strings.HasPrefix(digs(it, "target", "arn"), "arn:aws:iam::"+accountA+":role/") ||
			digs(it, "statement", "key") == "" || !strings.HasPrefix(digs(it, "claim"), "relationship:") {
			t.Errorf("edge = %s, want a current can_assume into an A role with its statement key", idetailJSON(it))
		}
		if digs(it, "target", "name") == "partner-access" {
			sids[digs(it, "statement", "sid")] = digs(it, "conditions", "StringEquals", "sts:ExternalId")
		}
	}
	if sids["PartnerA"] != "alpha" || sids["PartnerB"] != "beta" {
		t.Errorf("partner-access edges' statements = %v, want PartnerA/alpha and PartnerB/beta (two statements, two edges)", sids)
	}
	neg := items[0]
	if dig(neg, "statement", "negated") != true || digs(neg, "statement", "sid") != "" || dig(neg, "conditions") != nil {
		t.Errorf("negated-role edge = %s, want negated (NotAction, D-88), no Sid, no conditions", idetailJSON(neg))
	}
	if dig(items[1], "statement", "negated") != false {
		t.Errorf("partner-access edge = %s, want negated false", idetailJSON(items[1]))
	}
	if dig(body, "meta", "total_known") != true || num(body, "meta", "total") != 3 || dig(body, "meta", "next_cursor") != nil ||
		num(body, "meta", "limit") != 100 || digl(body, "meta", "coverage") == nil {
		t.Errorf("meta = %s, want the list envelope: total 3, no next page, limit 100, coverage", idetailJSON(body["meta"]))
	}

	// Paged: limit 1 walks every edge once; the cursor is bound to THIS
	// principal (D-62).
	var walked []string
	cursor := ""
	for page := 0; page < 5; page++ {
		args := []string{"limit", "1"}
		if cursor != "" {
			args = append(args, "cursor", cursor)
		}
		b := idetailGet(t, api, "/external-principals/"+cID.String()+"/referenced-by"+qs(args...))
		for _, it := range digl(b, "data") {
			walked = append(walked, digs(it, "claim"))
		}
		if cursor = digs(b, "meta", "next_cursor"); cursor == "" {
			break
		}
		if page == 0 {
			svcID := idetailExternalID(t, l, "aws", "lambda.amazonaws.com")
			code, eb := api.get("/external-principals/" + svcID.String() + "/referenced-by" + qs("cursor", cursor))
			if code != http.StatusBadRequest || errCode(eb) != "cursor_invalid" {
				t.Errorf("another principal's cursor = %d %s, want 400 cursor_invalid", code, idetailJSON(eb))
			}
		}
	}
	if len(walked) != 3 || walked[0] == walked[1] || walked[1] == walked[2] {
		t.Errorf("walked = %v, want the 3 edges once each", walked)
	}
}

// §2.12 / D-41 rule 1: a principal in an account that connects later gains a
// derived resolution -- unresolved_reason clears, the account reads
// connected. When every edge from a principal ends, it is derived retired
// (D-47) and its ended edges show on request.
func TestP2IdetailExternalResolvedAndRetired(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-external-resolved", true)
	a := l.account(accountA)
	reader := "arn:aws:iam::" + accountB + ":role/data-reader"
	trustRole(a, "reader-access", "AROAREADERACCESS0001", trustDoc(trustAllow(`{"AWS":"`+reader+`"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	api := l.api()
	epID := idetailExternalID(t, l, "aws", reader)
	path := "/external-principals/" + epID.String()
	before := dig(idetailGet(t, api, path), "data")
	if digs(before, "unresolved_reason") != "account_not_connected" || dig(before, "resolution") != nil {
		t.Fatalf("before B connects = %s, want unresolved, account not connected", idetailJSON(before))
	}

	b := l.account(accountB)
	b.role("data-reader", "AROADATAREADERDATARE")
	trustCycle(l, b, nil)
	readerID := idetailIdentityID(t, l, "data-reader")
	after := dig(idetailGet(t, api, path), "data")
	if dig(after, "unresolved_reason") != nil || digs(after, "resolution", "state") != models.ResolutionActive ||
		digs(after, "resolution", "basis") != models.BasisDerived || digs(after, "resolution", "rule") != models.ResolutionRuleExactARN ||
		digs(after, "resolution", "resolved_to") != refOf("identity", readerID) || dig(after, "resolution", "resolved_by") != nil ||
		dig(after, "account_connected") != true || dig(after, "account", "connected") != true {
		t.Errorf("after B connects = %s, want a derived exact_arn_match resolution to data-reader, account connected", idetailJSON(after))
	}

	// A drops the trust: the principal's one edge ends, and with it the
	// principal is derived retired (nothing names it any more).
	trustSetDoc(a, "reader-access", lambdaTrust)
	time.Sleep(10 * time.Millisecond)
	trustCycle(l, a, nil)
	gone := dig(idetailGet(t, api, path), "data")
	if digs(gone, "lifecycle") != models.IGALifecycleRetired || digs(gone, "state") != "ended" || digs(gone, "last_confirmed_at") == "" ||
		digs(gone, "retired_reason") != "no_longer_referenced" {
		t.Errorf("after its last edge ended = %s, want lifecycle retired (no_longer_referenced, §5.2), state ended, its last confirmation kept",
			idetailJSON(gone))
	}
	if n := len(digl(idetailGet(t, api, path+"/referenced-by"), "data")); n != 0 {
		t.Errorf("referenced-by lists %d edges by default, want 0: its only edge ended", n)
	}
	ended := digl(idetailGet(t, api, path+"/referenced-by"+qs("include_ended", "true")), "data")
	if len(ended) != 1 || digs(ended[0], "state") != "ended" || digs(ended[0], "ended_reason") != models.EndedNotSeen ||
		digs(ended[0], "valid_to") == "" {
		t.Errorf("include_ended = %s, want the one edge, ended not_seen, dated", idetailJSON(ended))
	}
}

// D-87's labels and account parsing for the kinds the lab above does not
// produce -- an EKS pod-identity service account, a SAML provider with no
// SAML:sub, an unresolved unique id. INSERTED DIRECTLY: the pod-identity and
// SAML paths are proven through the pipeline in the trust suites; this test
// is only about how the read names them. With no edge from them they are
// derived ended/retired (D-47).
func TestP2IdetailExternalLabels(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-external-labels", true)
	a := l.account(accountA)
	a.role("any-role", "AROAANYROLEANYROLEAN")
	l.scanAndProject(a)
	api := l.api()
	for _, tc := range []struct {
		mech, issuer, subject, name, reason string
	}{
		{models.ExternalPrincipalK8sServiceAccount, "oidc.eks.us-east-1.amazonaws.com/id/ABC123",
			"pod:system:serviceaccount:payments:api", "payments/api", "not_in_inventory"},
		{models.ExternalPrincipalSAML, "arn:aws:iam::" + accountA + ":saml-provider/Okta", "*",
			"arn:aws:iam::" + accountA + ":saml-provider/Okta · *", "wildcard"},
		{models.ExternalPrincipalAWSPrincipal, "aws", "AROAUNRESOLVEDID0001", "AROAUNRESOLVEDID0001", "not_in_inventory"},
	} {
		var id string
		if err := l.db.Raw(`INSERT INTO iga_external_principal (workspace_id, issuer, subject_claim, mechanism, source_key)
		                    VALUES (?, ?, ?, ?, ?) RETURNING id::text`,
			l.ws, tc.issuer, tc.subject, tc.mech, "idetail-label-"+tc.mech).Row().Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", tc.mech, err)
		}
		d := dig(idetailGet(t, api, "/external-principals/"+id), "data")
		if digs(d, "name") != tc.name || dig(d, "account") != nil || dig(d, "account_connected") != nil ||
			digs(d, "unresolved_reason") != tc.reason || digs(d, "state") != "ended" || digs(d, "lifecycle") != "retired" ||
			digs(d, "retired_reason") != "no_longer_referenced" || dig(d, "last_confirmed_at") != nil {
			t.Errorf("%s = %s, want name %q, no account, %s, derived ended/retired (no_longer_referenced) with no confirmation",
				tc.mech, idetailJSON(d), tc.name, tc.reason)
		}
	}
}

// §5.1 / D-3 / D-25: an external principal's account is connected AS OF THE
// REVISION -- a live connector for it with a run in the revision -- never as
// of the live connector table. Onboarding account B publishes nothing, so at
// the same revision its principals read exactly as before (not connected);
// "not in inventory" would claim we looked in an inventory that was never
// read. Once B's first scan publishes, a role ARN we hold no identity for is
// not_in_inventory, and B's root is account_principal -- "any principal B
// permits" names no single identity, even in a fully scanned account (§4.7).
// The used-by row that links to the principal says the same (§2.14.11).
func TestP2IdetailExternalConnectedAsOfRevision(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-external-revision", true)
	a := l.account(accountA)
	ghost := "arn:aws:iam::" + accountB + ":role/ghost"
	trustRole(a, "b-access", "AROABACCESSBACCESSBA", trustDoc(
		trustAllow(`{"AWS":"arn:aws:iam::`+accountB+`:root"}`, "sts:AssumeRole"),
		trustAllow(`{"AWS":"`+ghost+`"}`, "sts:AssumeRole")))
	trustCycle(l, a, nil)
	api := l.api()
	rootID, ghostID := idetailExternalID(t, l, "aws", accountB), idetailExternalID(t, l, "aws", ghost)
	roleID := idetailIdentityID(t, l, "b-access")
	type answer struct {
		rev                   int64
		connected, chip, used any
		reason                any
	}
	read := func(id uuid.UUID, name string) answer {
		t.Helper()
		body := idetailGet(t, api, "/external-principals/"+id.String())
		row := idetailByRef(t, digl(idetailGet(t, api, "/identities/"+roleID.String()+"/used-by"), "data", "principals", "items"),
			name, "principal", "name")
		return answer{rev: num(body, "meta", "rev"), connected: dig(body, "data", "account_connected"),
			chip: dig(body, "data", "account", "connected"), used: dig(row, "principal", "account", "connected"),
			reason: dig(body, "data", "unresolved_reason")}
	}
	want := func(label string, got answer, connected bool, reason string) {
		t.Helper()
		if got.connected != connected || got.chip != connected || got.used != connected || got.reason != reason {
			t.Errorf("%s = %+v, want account_connected, account.connected and the used-by chip all %v, unresolved_reason %s",
				label, got, connected, reason)
		}
	}
	root0, ghost0 := read(rootID, accountB), read(ghostID, ghost)
	want("B root before B is onboarded", root0, false, "account_not_connected")
	want("B's role before B is onboarded", ghost0, false, "account_not_connected")

	b := l.account(accountB) // onboarded: a live connector, nothing scanned, nothing published
	root1, ghost1 := read(rootID, accountB), read(ghostID, ghost)
	if root1.rev != root0.rev {
		t.Fatalf("rev moved from %v to %v on onboarding alone", root0.rev, root1.rev)
	}
	want("B root at the same revision after onboarding", root1, false, "account_not_connected")
	want("B's role at the same revision after onboarding", ghost1, false, "account_not_connected")

	trustCycle(l, b, nil) // B's first publication: its inventory, with no role named ghost
	root2, ghost2 := read(rootID, accountB), read(ghostID, ghost)
	if root2.rev <= root1.rev {
		t.Fatalf("rev = %v after B published, want above %v", root2.rev, root1.rev)
	}
	want("B root once B published", root2, true, "account_principal")
	want("B's unknown role once B published", ghost2, true, "not_in_inventory")
}
