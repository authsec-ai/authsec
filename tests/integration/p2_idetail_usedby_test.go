package integration

// GET /identities/:id/used-by (§5.3, T6.3; D-77 sections, D-62 cursor
// routes, D-12 include_ended, D-13 order, D-74 stale_reason): E5's shared
// role, the principals that may assume a role, a group's members -- one row
// per claim, never merged -- each section paged on its own.

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/authsec-ai/authsec/models"
)

// idetailTaskDef is an ECS task definition in us-east-1 of account A.
func idetailTaskDef(family, taskRole, execRole string) ecstypes.TaskDefinition {
	arn := "arn:aws:ecs:us-east-1:" + accountA + ":task-definition/" + family + ":1"
	return ecstypes.TaskDefinition{TaskDefinitionArn: aws.String(arn), Family: aws.String(family),
		TaskRoleArn: aws.String(taskRole), ExecutionRoleArn: aws.String(execRole),
		Status: ecstypes.TaskDefinitionStatusActive}
}

// idetailUsedByLab is a role used by a Lambda and two ECS task definitions,
// and trusted by the lab's Lambda service, a same-account role and account
// C's root under a condition; plus a group with two members.
func idetailUsedByLab(t *testing.T, name string) (*p2Lab, *p2Account, string, string) {
	l := newP2Lab(t, name, true)
	a := l.account(accountA)
	helper := a.role("helper", "AROAHELPERHELPERHELP")
	other := a.role("OtherRole", "AROAOTHERROLEOTHERRO")
	shared := trustRole(a, "SharedToolRole", "AROASHAREDTOOLROLE01", trustDoc(
		trustAllow(`{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole"),
		trustAllow(`{"AWS":"`+helper+`"}`, "sts:AssumeRole"),
		`{"Sid":"PartnerAccess","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::`+trustAccountC+`:root"},`+
			`"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"partner-42"}}}`))
	listsFunctions(a, "us-east-1", "ticket-tools", shared)
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aUser(a, "sam", "AIDASAMSAMSAMSAMSAM1")
	s3aJoin(a, "priya", "ops")
	s3aJoin(a, "sam", "ops")
	listsScanAndProjectECS(t, l, a,
		// The task role IS the execution role: two relationships, two rows.
		idetailTaskDef("ledger", shared, shared),
		// Used as the execution role only (task_execution_role, §2.2).
		idetailTaskDef("billing", other, shared))
	return l, a, shared, helper
}

func TestP2IdetailUsedBySharedRole(t *testing.T) {
	l, _, shared, helper := idetailUsedByLab(t, "p2-idetail-usedby")
	api := l.api()
	roleID := idetailIdentityID(t, l, "SharedToolRole")
	body := idetailGet(t, api, "/identities/"+roleID.String()+"/used-by")
	data := dig(body, "data").(map[string]any)
	if _, has := data["members"]; has || digs(data, "identity", "ref") != refOf("identity", roleID) ||
		digs(data, "identity", "kind") != models.CloudIdentityIAMRole {
		t.Errorf("role used-by = %s, want the identity header, workloads and principals, no members", idetailJSON(data))
	}

	// E5: every workload that uses it, with its relationship type, ONE ROW
	// PER CLAIM -- ledger's task role is also its execution role, so it is
	// two rows, never merged -- ordered by name.
	w := dig(data, "workloads").(map[string]any)
	items := digl(w, "items")
	if got := fmt.Sprint(idetailNames(items, "workload", "name")); got != "[billing ledger ledger ticket-tools]" {
		t.Fatalf("workloads = %v, want [billing ledger ledger ticket-tools]: %s", got, idetailJSON(items))
	}
	types := map[string][]string{}
	claims := map[string]bool{}
	for _, it := range items {
		types[digs(it, "workload", "name")] = append(types[digs(it, "workload", "name")], digs(it, "type"))
		claims[digs(it, "claim")] = true
		if digs(it, "basis") != models.BasisDeclared || digs(it, "state") != "current" || digs(it, "valid_from") == "" ||
			digs(it, "last_confirmed_at") == "" || digs(it, "workload", "account", "id") != accountA ||
			digs(it, "workload", "region") != "us-east-1" || dig(it, "valid_to") != nil {
			t.Errorf("workload row = %s, want declared, current, dated, account %s, us-east-1, no valid_to", idetailJSON(it), accountA)
		}
	}
	if len(claims) != 4 {
		t.Errorf("claims = %v, want 4 distinct relationships", claims)
	}
	if fmt.Sprint(types["billing"]) != "[task_execution_role]" || fmt.Sprint(types["ticket-tools"]) != "[executes_as]" ||
		len(types["ledger"]) != 2 || types["ledger"][0] == types["ledger"][1] {
		t.Errorf("relationship types = %v, want billing task_execution_role, ticket-tools executes_as, ledger both", types)
	}
	tt := idetailByRef(t, items, "ticket-tools", "workload", "name")
	if digs(tt, "workload", "runtime_kind") != models.WorkloadLambdaFunction ||
		digs(tt, "workload", "arn") != "arn:aws:lambda:us-east-1:"+accountA+":function:ticket-tools" {
		t.Errorf("ticket-tools = %s, want its runtime kind and ARN", idetailJSON(tt))
	}
	if dig(w, "total_known") != true || num(w, "total") != 4 || dig(w, "next_cursor") != nil {
		t.Errorf("workloads section = %s, want total 4, known, no next page", idetailJSON(w))
	}

	// Principals that may assume it: an identity and two external principals,
	// each with its mechanism, its statement and its conditions (verbatim).
	p := digl(data, "principals", "items")
	if got := fmt.Sprint(idetailNames(p, "principal", "name")); got != "["+trustAccountC+" helper lambda.amazonaws.com]" {
		t.Fatalf("principals = %v, want [%s helper lambda.amazonaws.com] (name order): %s", got, trustAccountC, idetailJSON(p))
	}
	h := idetailByRef(t, p, "helper", "principal", "name")
	if digs(h, "principal", "ref") != refOf("identity", idetailIdentityID(t, l, "helper")) ||
		digs(h, "principal", "kind") != models.CloudIdentityIAMRole || digs(h, "principal", "arn") != helper ||
		digs(h, "mechanism") != models.MechanismSTSAssumeRole || digs(h, "type") != models.RelTypeCanAssume ||
		dig(h, "conditions") != nil || digs(h, "statement", "key") == "" || digs(h, "principal", "account", "id") != accountA {
		t.Errorf("helper principal = %s, want the identity, iam_role, sts_assume_role, no conditions", idetailJSON(h))
	}
	c := idetailByRef(t, p, trustAccountC, "principal", "name")
	cID := idetailExternalID(t, l, "aws", trustAccountC)
	if digs(c, "principal", "ref") != refOf("external_principal", cID) || digs(c, "principal", "kind") != models.ExternalPrincipalAWSAccount ||
		dig(c, "principal", "arn") != nil || digs(c, "principal", "account", "id") != trustAccountC ||
		dig(c, "principal", "account", "connected") != false || digs(c, "statement", "sid") != "PartnerAccess" ||
		digs(c, "conditions", "StringEquals", "sts:ExternalId") != "partner-42" || dig(c, "statement", "negated") != false {
		t.Errorf("account C principal = %s, want the external aws_account, account not connected, Sid PartnerAccess, its condition", idetailJSON(c))
	}
	svc := idetailByRef(t, p, "lambda.amazonaws.com", "principal", "name")
	if digs(svc, "principal", "kind") != models.ExternalPrincipalAWSService || dig(svc, "principal", "account") != nil {
		t.Errorf("service principal = %s, want aws_service with no account", idetailJSON(svc))
	}
	_ = shared

	// A group: its members only. A user: nothing uses it.
	groupID := idetailIdentityID(t, l, "ops")
	g := dig(idetailGet(t, api, "/identities/"+groupID.String()+"/used-by"), "data").(map[string]any)
	if _, has := g["workloads"]; has || fmt.Sprint(idetailNames(digl(g, "members", "items"), "member", "name")) != "[priya sam]" {
		t.Errorf("group used-by = %s, want members [priya sam] only", idetailJSON(g))
	}
	m := digl(g, "members", "items")[0]
	if digs(m, "type") != models.RelTypeMemberOf || digs(m, "member", "kind") != models.CloudIdentityIAMUser ||
		digs(m, "member", "arn") != "arn:aws:iam::"+accountA+":user/priya" {
		t.Errorf("member row = %s, want priya's member_of", idetailJSON(m))
	}
	userID := idetailIdentityID(t, l, "priya")
	ud := dig(idetailGet(t, api, "/identities/"+userID.String()+"/used-by"), "data").(map[string]any)
	if len(ud) != 1 || ud["identity"] == nil {
		t.Errorf("user used-by = %s, want only the identity header: a user is used by nothing", idetailJSON(ud))
	}

	// Sections that do not apply, unknown sections, a cursor with no section.
	for path, param := range map[string]string{
		"/identities/" + roleID.String() + "/used-by" + qs("section", "members"):                   "section",
		"/identities/" + userID.String() + "/used-by" + qs("section", "workloads"):                 "section",
		"/identities/" + roleID.String() + "/used-by" + qs("section", "grants"):                    "section",
		"/identities/" + roleID.String() + "/used-by" + qs("cursor", "abc"):                        "cursor",
		"/identities/" + roleID.String() + "/used-by" + qs("section", "workloads", "limit", "201"): "limit",
	} {
		code, body := api.get(path)
		if code != http.StatusBadRequest || digs(body, "error", "parameter") != param {
			t.Errorf("GET %s = %d %s, want 400 naming %s", path, code, idetailJSON(body), param)
		}
	}
}

// Each section pages on its own (D-77): the first page of every section with
// its own cursor; ?section=&cursor= continues one; a cursor is bound to its
// identity, section and include_ended (D-62) and to the revision (§5.1).
func TestP2IdetailUsedByPaging(t *testing.T) {
	l, a, _, _ := idetailUsedByLab(t, "p2-idetail-usedby-paging")
	api := l.api()
	roleID := idetailIdentityID(t, l, "SharedToolRole")
	base := "/identities/" + roleID.String() + "/used-by"

	first := idetailGet(t, api, base+qs("limit", "1"))
	wc, pc := digs(first, "data", "workloads", "next_cursor"), digs(first, "data", "principals", "next_cursor")
	if wc == "" || pc == "" || len(digl(first, "data", "workloads", "items")) != 1 || num(first, "data", "workloads", "total") != 4 {
		t.Fatalf("first page = %s, want one row and a cursor per section, totals over the whole section", idetailJSON(first["data"]))
	}

	// Walk the workloads section to its end: every row once, in order.
	var walked []string
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		args := []string{"section", "workloads", "limit", "1"}
		if cursor != "" {
			args = append(args, "cursor", cursor)
		}
		b := idetailGet(t, api, base+qs(args...))
		if _, has := dig(b, "data").(map[string]any)["principals"]; has {
			t.Fatalf("section=workloads returned principals too: %s", idetailJSON(b["data"]))
		}
		for _, it := range digl(b, "data", "workloads", "items") {
			if seen[digs(it, "claim")] {
				t.Fatalf("claim %s repeated across pages", digs(it, "claim"))
			}
			seen[digs(it, "claim")] = true
			walked = append(walked, digs(it, "workload", "name"))
		}
		cursor = digs(b, "data", "workloads", "next_cursor")
		if cursor == "" {
			break
		}
	}
	if fmt.Sprint(walked) != "[billing ledger ledger ticket-tools]" {
		t.Errorf("walked = %v, want every workload row once, in name order", walked)
	}
	// The principals cursor from page one continues principals.
	p2 := idetailGet(t, api, base+qs("section", "principals", "limit", "1", "cursor", pc))
	if got := idetailNames(digl(p2, "data", "principals", "items"), "principal", "name"); fmt.Sprint(got) != "[helper]" {
		t.Errorf("principals page 2 = %v, want [helper]", got)
	}

	// A cursor is bound to its section, its identity and include_ended.
	other := idetailIdentityID(t, l, "helper")
	for path, what := range map[string]string{
		base + qs("section", "principals", "cursor", wc):                                        "another section",
		"/identities/" + other.String() + "/used-by" + qs("section", "workloads", "cursor", wc): "another identity",
		base + qs("section", "workloads", "cursor", wc, "include_ended", "true"):                "another filter",
		base + qs("section", "workloads", "cursor", wc+"x"):                                     "a forged signature",
	} {
		code, body := api.get(path)
		if code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
			t.Errorf("cursor for %s = %d %s, want 400 cursor_invalid", what, code, idetailJSON(body))
		}
	}
	// A stale rev, and a cursor from a superseded revision: 409 (§5.1).
	code, body := api.get(base + qs("rev", "9999"))
	if code != http.StatusConflict || errCode(body) != "revision_stale" {
		t.Errorf("rev=9999 = %d %s, want 409 revision_stale", code, idetailJSON(body))
	}
	time.Sleep(10 * time.Millisecond)
	listsScanAndProjectECS(t, l, a, idetailTaskDef("ledger", a.roleARN("SharedToolRole"), a.roleARN("SharedToolRole")))
	code, body = api.get(base + qs("section", "workloads", "limit", "1", "cursor", wc))
	if code != http.StatusConflict || errCode(body) != "revision_stale" {
		t.Errorf("cursor after a new publication = %d %s, want 409 revision_stale", code, idetailJSON(body))
	}

	// That publication ended billing's task_execution_role: gone by default,
	// back with include_ended (D-12), ended and dated.
	now := digl(idetailGet(t, api, base), "data", "workloads", "items")
	if got := fmt.Sprint(idetailNames(now, "workload", "name")); got != "[ledger ledger ticket-tools]" {
		t.Errorf("after billing is gone = %v, want [ledger ledger ticket-tools] (ended rows only on request)", got)
	}
	all := digl(idetailGet(t, api, base+qs("include_ended", "true")), "data", "workloads", "items")
	b := idetailByRef(t, all, "billing", "workload", "name")
	if len(all) != 4 || digs(b, "state") != "ended" || digs(b, "valid_to") == "" || digs(b, "ended_reason") == "" {
		t.Errorf("include_ended = %s, want billing's row back, ended with valid_to and ended_reason", idetailJSON(all))
	}
}

// A stale relationship is returned and marked, never dropped (D-12), with
// D-74's stale_reason naming the surface its partition could not read; the
// tab's meta.coverage says the same (D-73).
func TestP2IdetailUsedByStaleMembers(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-usedby-stale", true)
	a := l.account(accountA)
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aJoin(a, "priya", "ops")
	l.scanAndProject(a)
	a.iam.fail["GetAccountAuthorizationDetails:"+string(iamtypes.EntityTypeUser)] = denied("iam:GetAccountAuthorizationDetails")
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)

	groupID := idetailIdentityID(t, l, "ops")
	body := idetailGet(t, l.api(), "/identities/"+groupID.String()+"/used-by")
	items := digl(body, "data", "members", "items")
	if len(items) != 1 || digs(items[0], "state") != "stale" {
		t.Fatalf("members = %s, want priya's membership, STALE (iam_users denied), never dropped", idetailJSON(items))
	}
	reasons := digl(items[0], "stale_reason")
	var named bool
	for _, r := range reasons {
		if digs(r, "surface") == models.SurfaceIAMUsers && digs(r, "state") == models.CloudCoverageDenied && digs(r, "account_id") == accountA {
			named = true
		}
	}
	if !named {
		t.Errorf("stale_reason = %s, want iam_users denied in %s", idetailJSON(reasons), accountA)
	}
	var covered bool
	for _, c := range digl(body, "meta", "coverage") {
		if digs(c, "surface") == models.SurfaceIAMUsers && digs(c, "state") == models.CloudCoverageDenied && digs(c, "affects") != "" {
			covered = true
		}
	}
	if !covered {
		t.Errorf("meta.coverage = %s, want the iam_users gap named", idetailJSON(dig(body, "meta", "coverage")))
	}
	// The member itself is stale on its own detail, with the same reason.
	u := dig(idetailGet(t, l.api(), "/identities/"+idetailIdentityID(t, l, "priya").String()), "data")
	if digs(u, "state") != "stale" || len(digl(u, "stale_reason")) == 0 {
		t.Errorf("priya = %s, want stale with a stale_reason", idetailJSON(u))
	}
}

// D-44: a NotPrincipal trust statement produces no edge -- "everyone except
// X" names no one -- so the principals section cannot list who it lets in.
// It says so (not_principal_unresolved) rather than reading as "nobody may
// assume it"; a role without one carries no limitation.
func TestP2IdetailUsedByNotPrincipalLimitation(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-usedby-notprincipal", true)
	a := l.account(accountA)
	trustRole(a, "np-role", "AROANOTPRINCIPAL0001", trustDoc(
		`{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::`+trustAccountC+`:root"},"Action":"sts:AssumeRole"}`))
	a.role("plain-role", "AROAPLAINROLEPLAINRO")
	l.scanAndProject(a)
	api := l.api()

	np := dig(idetailGet(t, api, "/identities/"+idetailIdentityID(t, l, "np-role").String()+"/used-by"), "data", "principals")
	if len(digl(np, "items")) != 0 || fmt.Sprint(dig(np, "limitations")) != "[not_principal_unresolved]" {
		t.Errorf("NotPrincipal role's principals = %s, want no rows AND the not_principal_unresolved limitation", idetailJSON(np))
	}
	plain := dig(idetailGet(t, api, "/identities/"+idetailIdentityID(t, l, "plain-role").String()+"/used-by"), "data", "principals")
	if _, has := plain.(map[string]any)["limitations"]; has || len(digl(plain, "items")) != 1 {
		t.Errorf("plain role's principals = %s, want its Lambda service principal and no limitation", idetailJSON(plain))
	}
}
