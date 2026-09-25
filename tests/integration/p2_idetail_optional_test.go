package integration

// The detail routes under §5.1's failure contract and D-73/D-77's honesty
// rules: an optional count that times out is unknown, never guessed, and the
// response is still served; a surface the object's runs did not reach is
// named in meta.coverage; and a Permissions response that reaches its
// statement cap says truncated rather than silently stopping.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

// A real statement timeout, with no hook in production code: another session
// holds ACCESS EXCLUSIVE on the one table only the optional count reads
// (listsWithTableLocked), so the count waits until its savepoint's timeout.
func TestP2IdetailOptionalCountsTimeOut(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-optional", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", s3aDoc("ReadTickets", "s3:GetObject", "arn:aws:s3:::support-tickets/*")))
	listsFunctions(a, "us-east-1", "t1", role, "t2", role)
	l.scanAndProject(a)
	api := l.api()
	id := idetailIdentityID(t, l, "SharedToolRole")

	// used_by_count reads only iga_relationship; the detail reads nothing else
	// from it.
	listsWithTableLocked(t, l.db, "iga_relationship", func() {
		start := time.Now()
		d := dig(idetailGet(t, api, "/identities/"+id.String()), "data")
		if dig(d, "used_by_count", "value") != nil || dig(d, "used_by_count", "exact") != false || digs(d, "name") != "SharedToolRole" {
			t.Errorf("detail under a locked count = %s, want the detail with used_by_count {null, false}", idetailJSON(d))
		}
		if el := time.Since(start); el < igaread.RequestBudget/4 || el > igaread.RequestBudget {
			t.Errorf("request took %s: the count did not wait on the lock and time out inside the budget", el)
		}
	})
	if d := dig(idetailGet(t, api, "/identities/"+id.String()), "data"); num(d, "used_by_count", "value") != 2 {
		t.Errorf("used_by_count without the lock = %v, want 2", dig(d, "used_by_count"))
	}

	// revision_count reads only iga_statement_revision.
	listsWithTableLocked(t, l.db, "iga_statement_revision", func() {
		d := dig(idetailGet(t, api, "/identities/"+id.String()+"/permissions"), "data")
		st := idetailStatement(t, idetailPolicy(t, digl(d, "policies"), "TicketRead"), "ReadTickets")
		if dig(st, "revision_count") != nil || digs(st, "grant") == "" {
			t.Errorf("statement under a locked revision count = %s, want revision_count null and the rest served", idetailJSON(st))
		}
	})
}

// D-73: a detail carries the gaps of its object's own partitions' runs, with
// what each affects -- and only those that bear on it.
func TestP2IdetailDetailCoverage(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-coverage", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	s3aUser(a, "ci-deployer", "AIDACIDEPLOYER000001")
	a.iam.fail["ListAccessKeys"] = denied("iam:ListAccessKeys")
	run := l.scanAndProject(a)
	if s := s3aCoverage(run)[models.SurfaceIAMAccessKeys]; s.State == models.CloudCoverageReached {
		t.Fatalf("setup: iam_access_keys = %+v, want not reached", s)
	}
	api := l.api()
	user := idetailGet(t, api, "/identities/"+idetailIdentityID(t, l, "ci-deployer").String())
	var named bool
	for _, c := range digl(user, "meta", "coverage") {
		if digs(c, "surface") == models.SurfaceIAMAccessKeys && digs(c, "account_id") == accountA &&
			digs(c, "state") != models.CloudCoverageReached && strings.Contains(digs(c, "affects"), "access keys") {
			named = true
		}
	}
	if !named {
		t.Errorf("user meta.coverage = %s, want the iam_access_keys gap: its empty credentials list is not 'no keys'",
			idetailJSON(dig(user, "meta", "coverage")))
	}
	role := idetailGet(t, api, "/identities/"+idetailIdentityID(t, l, "SharedToolRole").String())
	for _, c := range digl(role, "meta", "coverage") {
		if digs(c, "surface") == models.SurfaceIAMAccessKeys {
			t.Errorf("role meta.coverage names %s: access keys do not bear on a role", idetailJSON(c))
		}
	}
}

// D-77: Permissions is unpaged with a hard statement cap; reaching it says
// truncated: true. The policy below has PermissionsStatementCap+1 distinct
// statements, collected and projected by the real pipeline.
func TestP2IdetailPermissionsStatementCap(t *testing.T) {
	l := newP2Lab(t, "p2-idetail-cap", true)
	a := l.account(accountA)
	a.role("BigRole", "AROABIGROLEBIGROLEBI")
	var stmts []string
	for i := 0; i <= igaread.PermissionsStatementCap; i++ {
		stmts = append(stmts, fmt.Sprintf(`{"Effect":"Allow","Action":"svc:Action%04d","Resource":"*"}`, i))
	}
	a.attach("BigRole", a.managed("Big", `{"Version":"2012-10-17","Statement":[`+strings.Join(stmts, ",")+`]}`))
	l.scanAndProject(a)
	d := dig(idetailGet(t, l.api(), "/identities/"+idetailIdentityID(t, l, "BigRole").String()+"/permissions"), "data")
	got := digl(idetailPolicy(t, digl(d, "policies"), "Big"), "statements")
	if d.(map[string]any)["truncated"] != true || len(got) != igaread.PermissionsStatementCap {
		t.Errorf("truncated = %v with %d statements, want true with exactly %d", dig(d, "truncated"), len(got), igaread.PermissionsStatementCap)
	}
	if len(got) > 0 && (num(got[0], "index") != 1 || num(got[len(got)-1], "index") != int64(igaread.PermissionsStatementCap)) {
		t.Errorf("first/last index = %d/%d, want 1/%d: the cap cuts in document order", num(got[0], "index"),
			num(got[len(got)-1], "index"), igaread.PermissionsStatementCap)
	}
}
