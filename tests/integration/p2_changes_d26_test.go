package integration

// D-26, the write side T5.4's run attribution rests on: ONE projection pass
// uses ONE timestamp -- its publication's published_at -- for every
// valid_from, valid_to, last_confirmed_at, first_seen_at, last_seen_at and
// lifecycle occurred_at it writes, so a start or an end is attributed to its
// revision and run EXACTLY by joining on (workspace_id, published_at).
//
// Driven through the real worker and projector over passes that exercise
// every writer of those columns: inserts, confirmations, a Sid edit (a
// revision closes and opens), a Sid-less edit (a statement retires and its
// grant ends), a detach (reconciliation ends an assignment and its grant), a
// policy recreated (RetirePolicyIncarnation), a role recreated
// (EndEdgesOnSubject), and a role gone (retireUnsupported's cascade).

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// changesTimed is one timestamp column a projection pass writes, with the run
// column it must agree with when the row names its run.
type changesTimed struct {
	table, column string
	where         string // extra predicate: provider, ...
	runCol        string // a run the timestamp must be the publication time of ("" when none)
	mustSee       bool   // the scenario must produce at least one non-null value
}

var changesTimedColumns = []changesTimed{
	{"iga_relationship", "valid_from", "", "", true},
	{"iga_relationship", "valid_to", "", "", true},
	{"iga_relationship", "last_confirmed_at", "", "last_confirmed_by", true},
	{"iga_policy_assignment", "valid_from", "", "", true},
	{"iga_policy_assignment", "valid_to", "", "", true},
	{"iga_policy_assignment", "last_confirmed_at", "", "last_confirmed_by", true},
	{"iga_access_edges", "valid_from", "provider = 'aws'", "", true},
	{"iga_access_edges", "valid_to", "provider = 'aws'", "", true},
	{"iga_access_edges", "last_confirmed_at", "provider = 'aws'", "last_confirmed_by", true},
	{"iga_object_support", "first_seen_at", "", "", true},
	{"iga_object_support", "last_confirmed_at", "", "last_confirmed_run_id", true},
	{"iga_statement_revision", "valid_from", "", "first_seen_run_id", true},
	{"iga_statement_revision", "valid_to", "", "", true},
	{"iga_lifecycle_event", "occurred_at", "", "scan_run_id", true},
	{"iga_identity_accounts", "first_seen_at", "provider = 'aws'", "", true},
	{"iga_identity_accounts", "last_seen_at", "provider = 'aws'", "", true},
	{"iga_workload", "first_seen_at", "provider = 'aws'", "", true},
	{"iga_workload", "last_seen_at", "provider = 'aws'", "", true},
	{"iga_resources", "first_seen_at", "provider = 'aws'", "", true},
	{"iga_resources", "last_seen_at", "provider = 'aws'", "", true},
	{"iga_policy", "first_seen_at", "provider = 'aws'", "", true},
	{"iga_policy", "last_seen_at", "provider = 'aws'", "", true},
	{"iga_entitlements", "first_seen_at", "provider = 'aws'", "", true},
	{"iga_entitlements", "last_seen_at", "provider = 'aws'", "", true},
	{"iga_credentials", "first_seen_at", "provider = 'aws'", "", true},
	{"iga_credentials", "last_seen_at", "provider = 'aws'", "", true},
	{"iga_external_principal", "first_seen_at", "", "", true},
	{"iga_external_principal", "last_seen_at", "", "", true},
}

// Safeguards (mutation-checked): the pass's one timestamp on the
// publication, on reconciliation's ends, and on edge inserts (never the
// column default now()); and the repository's refusal of a write without it.
func TestP2ChangesOnePassOneTimestamp(t *testing.T) {
	l := newP2Lab(t, "p2-changes-d26", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.role("GoneRole", "AROAGONEROLEGONEROLE")
	ticket := changesManaged(a, "TicketRead", docTicketRead)
	toolbox := changesManaged(a, "ToolboxRead", docToolboxRead)
	archive := changesManaged(a, "ArchiveRead", changesDocArchive)
	a.attach("SharedToolRole", ticket)
	a.attach("SharedToolRole", toolbox)
	a.attach("SharedToolRole", archive)
	a.attach("GoneRole", archive)
	a.lambda("us-east-1", "ticket-tools", role)
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	a.iam.keys["priya"] = []iamtypes.AccessKeyMetadata{{
		AccessKeyId: aws.String("AKIAPRIYAPRIYAPRIYA1"), UserName: aws.String("priya"),
		Status: iamtypes.StatusTypeActive, CreateDate: ago(0),
	}}
	l.scanAndProject(a)

	// A Sid edit, a Sid-less edit and a detach, in one pass.
	a.iam.managedPolicies[ticket] = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadTickets","Effect":"Allow",` +
		`"Action":["s3:GetObject","s3:ListBucket"],"Resource":"arn:aws:s3:::support-tickets/*"}]}`
	a.iam.managedPolicies[toolbox] = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::support-tickets/*"}]}`
	a.detach("SharedToolRole", archive)
	l.scanAndProject(a)

	// A policy recreated, and a role recreated.
	a.iam.policyIDs[ticket] = "ANPARECREATEDTICKET2"
	a.role("SharedToolRole", "AROARECREATEDROLE002")
	l.scanAndProject(a)

	// A role gone: support ends, it retires, its edges end in the cascade.
	var keep []iamtypes.Role
	for _, r := range a.iam.roles {
		if aws.ToString(r.RoleName) != "GoneRole" {
			keep = append(keep, r)
		}
	}
	a.iam.roles = keep
	l.scanAndProject(a)

	// The join is exact only if no two publications share a time.
	if n := l.count(`SELECT count(*) FROM (SELECT published_at FROM iga_publication WHERE workspace_id = ?
	                  GROUP BY published_at HAVING count(*) > 1) d`, l.ws); n != 0 {
		t.Fatalf("%d published_at values shared by two publications", n)
	}

	for _, c := range changesTimedColumns {
		where := "t.workspace_id = ?"
		if c.where != "" {
			where += " AND t." + c.where
		}
		seen := l.count(fmt.Sprintf(`SELECT count(*) FROM %s t WHERE %s AND t.%s IS NOT NULL`, c.table, where, c.column), l.ws)
		if c.mustSee && seen == 0 {
			t.Errorf("%s.%s: the scenario wrote none, so it proves nothing", c.table, c.column)
			continue
		}
		// Every value is some publication's published_at ...
		stray := l.count(fmt.Sprintf(`SELECT count(*) FROM %s t WHERE %s AND t.%s IS NOT NULL
		              AND NOT EXISTS (SELECT 1 FROM iga_publication p
		                               WHERE p.workspace_id = t.workspace_id AND p.published_at = t.%s)`,
			c.table, where, c.column, c.column), l.ws)
		if stray != 0 {
			t.Errorf("%s.%s: %d of %d values are no publication's published_at", c.table, c.column, stray, seen)
		}
		// ... and, where the row names its run, THAT run's publication's.
		if c.runCol != "" {
			wrong := l.count(fmt.Sprintf(`SELECT count(*) FROM %s t
			              JOIN iga_publication p ON p.workspace_id = t.workspace_id AND p.scan_run_id = t.%s
			             WHERE %s AND t.%s IS NOT NULL AND p.published_at <> t.%s`,
				c.table, c.runCol, where, c.column, c.column), l.ws)
			if wrong != 0 {
				t.Errorf("%s.%s: %d values are not the publication time of their own %s", c.table, c.column, wrong, c.runCol)
			}
		}
	}
	// A lifecycle event's stored revision is the publication at its time.
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event le
	                   JOIN iga_publication p ON p.workspace_id = le.workspace_id AND p.rev = le.rev
	                  WHERE le.workspace_id = ? AND (p.published_at <> le.occurred_at OR p.scan_run_id <> le.scan_run_id)`,
		l.ws); n != 0 {
		t.Errorf("%d lifecycle events disagree with the publication of their rev", n)
	}
	// Every end came after its start.
	for _, table := range []string{"iga_relationship", "iga_policy_assignment", "iga_access_edges", "iga_statement_revision"} {
		if n := l.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ? AND valid_to < valid_from`, l.ws); n != 0 {
			t.Errorf("%s: %d rows end before they start", table, n)
		}
	}
}
