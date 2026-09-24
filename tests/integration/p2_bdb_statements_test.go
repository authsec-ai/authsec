package integration

// B11 (SPEC-iga-phase2-graph.md §7.3; §2.6 statement identity, l.508-525;
// §2.7 rows "reorder", "Sid edit", "Sid-less edit"; §7.1 E7), through the REAL
// scan worker and projector: a reorder keeps every statement id; an edit of a
// Sid-keyed statement keeps its id and adds ONE revision; an edit of a Sid-less
// statement is a replacement -- the old one retires, a new one begins.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// bdbStmt is one statement of the fixture's policy, in document order.
type bdbStmt struct{ sid, action string }

func bdbPolicyDoc(stmts ...bdbStmt) string {
	parts := make([]string, 0, len(stmts))
	for _, s := range stmts {
		sid := ""
		if s.sid != "" {
			sid = `"Sid":"` + s.sid + `",`
		}
		parts = append(parts, `{`+sid+`"Effect":"Allow","Action":"`+s.action+`","Resource":"arn:aws:s3:::support-tickets/*"}`)
	}
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(parts, ",") + `]}`
}

// bdbStatementRow is a statement with its grant, as B11 reads them.
type bdbStatementRow struct {
	ID            uuid.UUID
	Sid           string
	Index         int
	ContentHash   string
	Lifecycle     string
	RetiredReason string
	Action        string
	Grant         *uuid.UUID
	GrantState    *string
	GrantReason   *string
}

// bdbStatements is every statement of the policy (retired ones too), keyed by
// a label: the Sid, else its action -- what a person would call it.
func bdbStatements(t *testing.T, l *p2Lab, policy string) map[string][]bdbStatementRow {
	t.Helper()
	var rows []bdbStatementRow
	if err := l.db.Raw(`
		SELECT e.id, e.sid, e.statement_index AS index, e.content_hash, e.lifecycle, e.retired_reason,
		       e.native_rights->>'Action' AS action,
		       g.id AS grant, g.state AS grant_state, g.ended_reason AS grant_reason
		  FROM iga_entitlements e
		  JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
		  LEFT JOIN iga_access_edges g ON g.workspace_id = e.workspace_id AND g.entitlement_id = e.id
		 WHERE e.workspace_id = ? AND e.provider = 'aws' AND p.display_name = ?
		 ORDER BY e.first_seen_at, g.valid_from`, l.ws, policy).Scan(&rows).Error; err != nil {
		t.Fatalf("statements of %s: %v", policy, err)
	}
	out := map[string][]bdbStatementRow{}
	for _, r := range rows {
		label := r.Sid
		if label == "" {
			label = r.Action
		}
		out[label] = append(out[label], r)
	}
	return out
}

// bdbOne is the single row under a label.
func bdbOne(t *testing.T, m map[string][]bdbStatementRow, label string) bdbStatementRow {
	t.Helper()
	if len(m[label]) != 1 {
		t.Fatalf("statement %q = %+v, want exactly one row (with its one grant)", label, m[label])
	}
	return m[label][0]
}

type bdbRevision struct {
	ContentHash     string
	PolicyVersionID string
	ValidFrom       time.Time
	ValidTo         *time.Time
	FirstSeenRunID  uuid.UUID
}

func bdbRevisions(t *testing.T, l *p2Lab, stmt uuid.UUID) []bdbRevision {
	t.Helper()
	var out []bdbRevision
	if err := l.db.Raw(`SELECT content_hash, policy_version_id, valid_from, valid_to, first_seen_run_id
	                      FROM iga_statement_revision WHERE workspace_id = ? AND entitlement_id = ?
	                     ORDER BY valid_from`, l.ws, stmt).Scan(&out).Error; err != nil {
		t.Fatalf("revisions of %s: %v", stmt, err)
	}
	return out
}

// B11: Toolbox, a customer-managed policy on SharedToolRole, holds two
// Sid-keyed statements (ReadTickets, ListTickets) and two Sid-less ones
// (s3:GetObjectTagging, s3:GetObjectAcl), each with one grant.
//
//	(a) The document is REVERSED. Every statement keeps its id and its grant;
//	    statement_index follows the new order; no revision is written (the
//	    content did not change).
//	(b) ReadTickets' Action is edited, in a new policy version v4. Same
//	    statement id, content_hash moved, exactly TWO revisions -- the old one
//	    closed at this pass's published_at, the new one live with the new hash
//	    and policy_version_id v4 -- and its grant is the same row, current.
//	(c) The Sid-less s3:GetObjectTagging becomes s3:PutObjectTagging. That is a
//	    REPLACEMENT: the old statement retires unsupported with its support
//	    ended and its grant ended (not_seen: its partition closes it before the
//	    retirement cascade, D-67); a NEW statement with a new id and a new
//	    current grant. The untouched Sid-less statement keeps its id.
//
// Safeguard (mutation-checked): statements are keyed by Sid or content, never
// by position (StatementKey) -- index-keyed, the reorder moves ids between
// statements.
func TestP2BdbStatementIdentity(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-b11", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	stmts := []bdbStmt{
		{"ReadTickets", "s3:GetObject"}, {"", "s3:GetObjectTagging"},
		{"ListTickets", "s3:ListBucket"}, {"", "s3:GetObjectAcl"},
	}
	arn := a.managed("Toolbox", bdbPolicyDoc(stmts...))
	a.attach("SharedToolRole", arn)
	l.scanAndProject(a)

	s1 := bdbStatements(t, l, "Toolbox")
	labels := []string{"ReadTickets", "s3:GetObjectTagging", "ListTickets", "s3:GetObjectAcl"}
	ids := map[string]uuid.UUID{}
	grants := map[string]uuid.UUID{}
	for i, lb := range labels {
		r := bdbOne(t, s1, lb)
		if r.Index != i || r.Grant == nil || *r.GrantState != models.RelCurrent {
			t.Fatalf("setup: %s = %+v, want index %d with a current grant", lb, r, i)
		}
		ids[lb], grants[lb] = r.ID, *r.Grant
	}
	revisions := l.count(`SELECT count(*) FROM iga_statement_revision WHERE workspace_id = ?`, l.ws)
	if revisions != 2 {
		t.Fatalf("setup: %d revisions, want 2 (the Sid-keyed statements; a Sid-less one is replaced, never revised)", revisions)
	}

	t.Run("reorder keeps every id", func(t *testing.T) {
		rev := []bdbStmt{stmts[3], stmts[2], stmts[1], stmts[0]}
		a.iam.managedPolicies[arn] = bdbPolicyDoc(rev...)
		time.Sleep(10 * time.Millisecond)
		l.scanAndProject(a)
		s := bdbStatements(t, l, "Toolbox")
		for i, want := range []string{"s3:GetObjectAcl", "ListTickets", "s3:GetObjectTagging", "ReadTickets"} {
			r := bdbOne(t, s, want)
			if r.ID != ids[want] || r.Index != i || r.Lifecycle != models.IGALifecycleActive {
				t.Errorf("%s after the reorder = %+v, want the same id %s at index %d", want, r, ids[want], i)
			}
			if r.Grant == nil || *r.Grant != grants[want] || *r.GrantState != models.RelCurrent {
				t.Errorf("%s's grant after the reorder = %v (%v), want the same grant %s, current", want, r.Grant, r.GrantState, grants[want])
			}
		}
		if n := l.count(`SELECT count(*) FROM iga_statement_revision WHERE workspace_id = ?`, l.ws); n != revisions {
			t.Errorf("revisions %d -> %d: a reorder changed no statement's content", revisions, n)
		}
		stmts = rev
	})

	t.Run("a Sid edit is a revision", func(t *testing.T) {
		for i := range stmts {
			if stmts[i].sid == "ReadTickets" {
				stmts[i].action = "s3:GetObjectVersion"
			}
		}
		a.iam.managedPolicies[arn] = bdbPolicyDoc(stmts...)
		a.iam.policyVersions[arn] = "v4"
		before := bdbOne(t, bdbStatements(t, l, "Toolbox"), "ReadTickets")
		time.Sleep(10 * time.Millisecond)
		run := l.scanAndProject(a)
		at := bdbPublishedAt(t, l, run.ID)

		r := bdbOne(t, bdbStatements(t, l, "Toolbox"), "ReadTickets")
		if r.ID != ids["ReadTickets"] || r.ContentHash == before.ContentHash || r.Action != "s3:GetObjectVersion" {
			t.Errorf("ReadTickets after the edit = %+v, want the same id %s with its new content", r, ids["ReadTickets"])
		}
		if r.Grant == nil || *r.Grant != grants["ReadTickets"] || *r.GrantState != models.RelCurrent {
			t.Errorf("ReadTickets' grant after the edit = %v (%v), want the same grant, current", r.Grant, r.GrantState)
		}
		revs := bdbRevisions(t, l, r.ID)
		if len(revs) != 2 {
			t.Fatalf("ReadTickets revisions = %+v, want exactly 2", revs)
		}
		if revs[0].ContentHash != before.ContentHash || revs[0].ValidTo == nil || !revs[0].ValidTo.Equal(at) {
			t.Errorf("old revision = %+v, want the old content closed at this pass (%s)", revs[0], at)
		}
		if revs[1].ContentHash != r.ContentHash || revs[1].ValidTo != nil || revs[1].PolicyVersionID != "v4" ||
			revs[1].FirstSeenRunID != run.ID || !revs[1].ValidFrom.Equal(at) {
			t.Errorf("new revision = %+v, want live, the new content, policy version v4, first seen by run %s", revs[1], run.ID)
		}
		if n := l.count(`SELECT count(*) FROM iga_entitlements e JOIN iga_policy p ON p.id = e.policy_id
		                  WHERE e.workspace_id = ? AND p.display_name = 'Toolbox'`, l.ws); n != 4 {
			t.Errorf("Toolbox statements = %d, want still 4: a Sid edit creates no statement", n)
		}
	})

	t.Run("a Sid-less edit is a replacement", func(t *testing.T) {
		for i := range stmts {
			if stmts[i].action == "s3:GetObjectTagging" {
				stmts[i].action = "s3:PutObjectTagging"
			}
		}
		a.iam.managedPolicies[arn] = bdbPolicyDoc(stmts...)
		time.Sleep(10 * time.Millisecond)
		run := l.scanAndProject(a)
		at := bdbPublishedAt(t, l, run.ID)
		s := bdbStatements(t, l, "Toolbox")

		old := bdbOne(t, s, "s3:GetObjectTagging")
		if old.ID != ids["s3:GetObjectTagging"] || old.Lifecycle != models.IGALifecycleRetired ||
			old.RetiredReason != models.RetiredUnsupported {
			t.Errorf("the edited Sid-less statement = %+v, want %s retired unsupported", old, ids["s3:GetObjectTagging"])
		}
		if old.Grant == nil || *old.GrantState != models.RelEnded || *old.GrantReason != models.EndedNotSeen {
			t.Errorf("its grant = %v (%v, %v), want ended not_seen", old.Grant, old.GrantState, old.GrantReason)
		}
		if st := l.supportOf("entitlement_id", old.ID)[a.conn]; st != models.RelEnded {
			t.Errorf("its support = %q, want ended", st)
		}
		neu := bdbOne(t, s, "s3:PutObjectTagging")
		if neu.ID == old.ID || neu.Lifecycle != models.IGALifecycleActive || neu.Grant == nil ||
			*neu.Grant == *old.Grant || *neu.GrantState != models.RelCurrent {
			t.Errorf("the replacement = %+v, want a NEW active statement with a NEW current grant", neu)
		}
		var validFrom time.Time
		l.db.Raw(`SELECT valid_from FROM iga_access_edges WHERE id = ?`, *neu.Grant).Scan(&validFrom)
		if !validFrom.Equal(at) {
			t.Errorf("the new grant starts at %s, want this pass (%s)", validFrom, at)
		}
		if acl := bdbOne(t, s, "s3:GetObjectAcl"); acl.ID != ids["s3:GetObjectAcl"] || acl.Lifecycle != models.IGALifecycleActive {
			t.Errorf("the untouched Sid-less statement = %+v, want the same id %s, active", acl, ids["s3:GetObjectAcl"])
		}
		if n := len(bdbRevisions(t, l, neu.ID)); n != 0 {
			t.Errorf("the replacement has %d revisions, want none: a Sid-less statement is replaced, never revised", n)
		}
	})
}
