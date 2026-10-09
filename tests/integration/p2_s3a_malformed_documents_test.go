package integration

// S3a (T3.3; §1.3 "One malformed document ... isolate per document;
// policy_documents: partial names it", E9): a document that was fetched and
// is not a policy at all -- not JSON -- as opposed to one that could not be
// fetched (TestP2S3aOneUnreadableDocumentIsolated) or one with an unusable
// statement (TestP2S3aUnusableStatementMarksDocumentUnreadable, D-49).
//
// It is the one path where nothing but UnreadableDocuments keeps the legacy
// reconcile off: the document does not parse, so writePolicyDocument never
// runs and neither ParseFailures nor StatementsSkipped moves.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// s3aMalformed is a document IAM returned and no parser can read: cut off in
// the middle of a statement.
const s3aMalformed = `{"Version":"2012-10-17","Statement":[{"Sid":"Cut","Effect":`

// One inline document malformed, then a customer-managed one as well, then
// both fixed. While a document is malformed: its row carries a parse:
// document_error and no document, policy_documents is partial and names it
// (items and prose), its statements and grants go STALE -- never ended --
// every other policy stays current, and the Cloud Inventory permissions it
// produced last time are KEPT (the legacy reconcile must not run over a
// document this run could not read).
func TestP2S3aMalformedDocumentsIsolated(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-malformed", true)
	a := l.account(accountA)
	a.role("MalformedRole", "AROAMALFORMEDROLE001")
	custDoc := s3aDoc("CustRead", "s3:GetObject", "arn:aws:s3:::cust-broken/*")
	inlineDoc := s3aDoc("InlineRead", "sqs:SendMessage", "arn:aws:sqs:us-east-1:"+a.id+":inline-broken")
	cust := a.managed("CustBroken", custDoc)
	intact := a.managed("Intact", s3aDoc("IntactRead", "s3:GetObject", "arn:aws:s3:::intact/*"))
	a.attach("MalformedRole", cust)
	a.attach("MalformedRole", intact)
	inline := map[string]string{
		"InlineBroken": inlineDoc,
		"InlineIntact": s3aDoc("InlineIntactRead", "sqs:ReceiveMessage", "arn:aws:sqs:us-east-1:"+a.id+":inline-intact"),
	}
	a.iam.inlineRolePolicies["MalformedRole"] = inline
	first := l.scanAndProject(a)

	const inlineItem = "InlineBroken (inline on MalformedRole)"
	// check asserts one run's picture; broken maps each malformed policy's
	// name to its statement key and its legacy cloud_permission native id.
	check := func(step string, run models.CloudScanRun, broken map[string][2]string, wantItems []string) {
		t.Helper()
		pols := s3aCloudPolicies(l, a.conn, run.Generation)
		cov := s3aCoverage(run)
		pd, reported := cov[models.SurfacePolicyDocuments]
		if len(broken) == 0 {
			if reported {
				t.Errorf("%s: policy_documents = %+v, want absent: every document reads", step, pd)
			}
		} else {
			if !reported || pd.State != models.CloudCoveragePartial || pd.Truncated {
				t.Errorf("%s: policy_documents = %+v (reported %v), want partial", step, pd, reported)
			}
			var items []string
			for _, it := range pd.Items {
				items = append(items, it.Policy+"|"+it.Version)
			}
			if strings.Join(items, ",") != strings.Join(wantItems, ",") {
				t.Errorf("%s: policy_documents items = %v, want %v", step, items, wantItems)
			}
			noun := "policies"
			if len(broken) == 1 {
				noun = "policy"
			}
			if !strings.HasPrefix(pd.Error, fmt.Sprintf("%d %s could not be read: ", len(broken), noun)) {
				t.Errorf("%s: policy_documents prose = %q, want it to count %d unreadable", step, pd.Error, len(broken))
			}
		}
		for _, surf := range []string{models.SurfaceIAMPolicies, models.SurfaceIAMRoles} {
			if s := cov[surf].State; s != models.CloudCoverageReached {
				t.Errorf("%s: %s = %q, want reached: a malformed document never vetoes a listing", step, surf, s)
			}
		}
		if _, bad := cov[models.SurfacePermissionScan]; bad {
			t.Errorf("%s: permission_scan = %+v: the permission scan aborted over a document", step, cov[models.SurfacePermissionScan])
		}

		sup := s3aStatementSupport(l, a.conn)
		grants := map[string]string{}
		for _, g := range s3aGrantsByHolder(l) {
			grants[g.Policy] = g.State
		}
		for _, name := range []string{"CustBroken", "Intact", "InlineBroken", "InlineIntact"} {
			row, ok := pols[name]
			want, wantDoc, wantErr := models.RelCurrent, true, ""
			if _, isBroken := broken[name]; isBroken {
				want, wantDoc, wantErr = models.RelStale, false, "parse: "
			}
			switch {
			case !ok:
				t.Errorf("%s: %s has no cloud_policy row at this generation: its attachment is a fact read without the document", step, name)
			case row.HasDocument != wantDoc || !strings.HasPrefix(row.DocumentError, wantErr) ||
				(wantErr == "" && row.DocumentError != ""):
				t.Errorf("%s: %s row = %+v, want document %v and document_error %q...", step, name, row, wantDoc, wantErr)
			}
			if grants[name] != want {
				t.Errorf("%s: %s grant = %q, want %s", step, name, grants[name], want)
			}
			if b, isBroken := broken[name]; isBroken {
				if s := sup[b[0]]; s != models.IGALifecycleActive+":"+models.RelStale {
					t.Errorf("%s: statement %s = %q, want active:stale -- not confirmed, never retired", step, b[0], s)
				}
				// Cloud Inventory keeps what the document produced when it last
				// read: this run's legacy reconcile must not have deleted it.
				if n := l.count(`SELECT count(*) FROM cloud_permission WHERE workspace_id = ? AND connector_id = ?
				                  AND native_id = ?`, l.ws, a.conn, b[1]); n == 0 {
					t.Errorf("%s: cloud_permission %s deleted over a document this run could not read", step, b[1])
				}
			}
		}
		if n := l.count(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND state = 'ended'`, l.ws); n != 0 {
			t.Errorf("%s: %d grants ended, want none: nothing was detached", step, n)
		}
	}

	check("all readable", first, nil, nil)
	for _, k := range []string{"Intact/IntactRead", "InlineIntact/InlineIntactRead"} {
		if s := s3aStatementSupport(l, a.conn)[k]; s != models.IGALifecycleActive+":"+models.RelCurrent {
			t.Fatalf("statement %s = %q, want active:current before anything breaks", k, s)
		}
	}

	// The inline document alone: nothing else in the run is unreadable, so
	// naming it is the only thing between it and the legacy reconcile.
	inline["InlineBroken"] = s3aMalformed
	run := l.scanAndProject(a)
	check("inline malformed", run, map[string][2]string{
		"InlineBroken": {"InlineBroken/InlineRead", "inline:InlineBroken#s0"},
	}, []string{inlineItem + "|"})
	if row := s3aCloudPolicies(l, a.conn, run.Generation)["InlineBroken"]; row.DocumentError == "" ||
		!strings.Contains(s3aCoverage(run)[models.SurfacePolicyDocuments].Error, inlineItem+" ("+row.DocumentError+")") {
		t.Errorf("policy_documents prose = %q, want it to name %s with its row's error %q",
			s3aCoverage(run)[models.SurfacePolicyDocuments].Error, inlineItem, row.DocumentError)
	}
	for _, k := range []string{"Intact/IntactRead", "InlineIntact/InlineIntactRead", "CustBroken/CustRead"} {
		if s := s3aStatementSupport(l, a.conn)[k]; s != models.IGALifecycleActive+":"+models.RelCurrent {
			t.Errorf("statement %s = %q, want active:current: one document's failure is its own", k, s)
		}
	}

	// And a customer-managed one besides, from the LocalManagedPolicy listing.
	a.iam.managedPolicies[cust] = s3aMalformed
	run = l.scanAndProject(a)
	check("both malformed", run, map[string][2]string{
		"InlineBroken": {"InlineBroken/InlineRead", "inline:InlineBroken#s0"},
		"CustBroken":   {"CustBroken/CustRead", cust + "#s0"},
	}, []string{"CustBroken|v3", inlineItem + "|"})

	// Fixed in AWS: the errors clear, the statements are confirmed again, and
	// policy_documents is gone.
	inline["InlineBroken"] = inlineDoc
	a.iam.managedPolicies[cust] = custDoc
	run = l.scanAndProject(a)
	check("fixed", run, nil, nil)
	for _, k := range []string{"CustBroken/CustRead", "InlineBroken/InlineRead"} {
		if s := s3aStatementSupport(l, a.conn)[k]; s != models.IGALifecycleActive+":"+models.RelCurrent {
			t.Errorf("statement %s = %q after the fix, want active:current", k, s)
		}
	}
}
