package integration

// T6.10 follow-up: the Changes total (§5.2, D-27) counts each event ONCE.
//
// T6.10 moved the total off one DISTINCT over every branch of the union: only
// the branches that can repeat an event are deduplicated, the rest stream
// straight into the LIMIT (changesUnion.countSQL). That is exact only while
// every branch that CAN repeat an event is marked repeatable. The branches
// that can, and the lab state that makes each one repeat here:
//
//   - statement_revised on a WORKLOAD: one row per execution identity holding
//     a grant to the statement when it was revised. The workload switches from
//     RoleA to RoleB in the pass that revises a statement both roles hold, so
//     at that instant both executes_as edges are valid (inclusive at both
//     ends, D-27d) and both reach the one revision.
//   - statement_replaced: its id is derived from (policy, run) (D-27c), so
//     every Sid-less statement of the policy retired in the run names the one
//     event. The pass edits BOTH Sid-less statements of the policy.
//   - statement_replaced on a RESOURCE: the ended statements and the ones that
//     began in their place all name it, and each reaches the one event.
//
// The page dedupes with DISTINCT ON either way, so a wrongly marked branch
// shows in the total: it would count one event several times while the list
// shows it once, and a client paging to the stated total would wait for
// events that do not exist. It shows in small pages too (see below).

import (
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const (
	// loadDocToolboxV1: a Sid-keyed statement and two Sid-less ones, all
	// Allow; the Sid-less pair names one bucket.
	loadDocToolboxV1 = `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"ReadTickets","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"},` +
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ticket-archive/*"},` +
		`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::ticket-archive/*"}]}`
	// loadDocToolboxV2 edits all three: the Sid-keyed one gains a revision,
	// the two Sid-less ones are replaced (new content, new keys).
	loadDocToolboxV2 = `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"ReadTickets","Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::support-tickets/*"},` +
		`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::ticket-archive/*"},` +
		`{"Effect":"Allow","Action":["s3:ListBucket","s3:GetBucketLocation"],"Resource":"arn:aws:s3:::ticket-archive/*"}]}`
)

// Every object's Changes total equals the number of distinct events its
// pages list, where several union branches reach one event.
//
// Safeguards (mutation-checked): the workload's statement_revised branch, the
// holders' statement_replaced branch and the resource's statement_replaced
// branch are counted with DISTINCT (addRepeatable), and deduplicated before
// the page cuts them (pageSQL).
func TestP2LoadChangesTotalCountsEachEventOnce(t *testing.T) {
	l := newP2Lab(t, "p2-load-changes-total", true)
	a := l.account(accountA)
	roleA := a.role("RoleA", "AROAROLEAAAAAAAAAAAA")
	roleB := a.role("RoleB", "AROAROLEBBBBBBBBBBBB")
	toolbox := changesManaged(a, "SharedToolbox", loadDocToolboxV1)
	a.attach("RoleA", toolbox)
	a.attach("RoleB", toolbox)
	a.lambda("us-east-1", "fn", roleA)
	l.scanAndProject(a)

	// One pass: the workload switches roles and the policy is edited.
	a.lambda("us-east-1", "fn", roleB)
	a.iam.managedPolicies[toolbox] = loadDocToolboxV2
	a.iam.policyVersions[toolbox] = "v4"
	l.scanAndProject(a)

	api := l.api()
	toolboxRef := refOf("policy", changesPolicy(t, l, "SharedToolbox"))
	wl := changesIDOf(t, l, `SELECT id FROM iga_workload WHERE workspace_id = ?`, l.ws)
	resource := func(text string) uuid.UUID {
		return changesIDOf(t, l, `SELECT id FROM iga_resources WHERE workspace_id = ? AND display_name = ?`, l.ws, text)
	}

	for _, c := range []struct {
		name    string
		refType string
		id      uuid.UUID
		// want: the events that must each be listed exactly once -- the ones
		// several branches reach.
		want map[string]int
	}{
		{"workload fn (switched roles)", "workload", wl,
			map[string]int{"statement_revised": 1, "statement_replaced": 1}},
		{"identity RoleA", "identity", changesIdentity(t, l, "RoleA"),
			map[string]int{"statement_revised": 1, "statement_replaced": 1}},
		{"resource ticket-archive/*", "resource", resource("arn:aws:s3:::ticket-archive/*"),
			map[string]int{"statement_replaced": 1}},
		{"resource support-tickets/*", "resource", resource("arn:aws:s3:::support-tickets/*"),
			map[string]int{"statement_revised": 1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			all := changesAll(t, api, c.refType, c.id, "configuration")
			changesAssertAttributed(t, l, all)
			ids := map[string]bool{}
			byEvent := map[string]int{}
			for _, e := range all {
				id := digs(e, "id")
				if ids[id] {
					t.Errorf("event %s listed twice:%s", id, changesDump(all))
				}
				ids[id] = true
				byEvent[digs(e, "event")]++
			}
			for event, n := range c.want {
				if byEvent[event] != n {
					t.Errorf("%d %s events, want %d (the setup must make several branches reach one):%s",
						byEvent[event], event, n, changesDump(all))
				}
			}
			if got := changesPick(all, "statement_replaced", "subject", toolboxRef); c.want["statement_replaced"] > 0 && len(got) != 1 {
				t.Errorf("statement_replaced of SharedToolbox = %d events, want 1", len(got))
			}

			page := changesGet(t, api, changesPath(c.refType, c.id, "limit", "200"))
			if dig(page, "meta", "total_known") != true || num(page, "meta", "total") != int64(len(ids)) {
				t.Errorf("meta total = %v (known %v), but the pages list %d distinct events: a branch that repeats an event is counted without DISTINCT",
					dig(page, "meta", "total"), dig(page, "meta", "total_known"), len(ids))
			}

			// Small pages list the same events in the same order. The page
			// statement cuts every branch to limit+1 rows BEFORE merging them
			// (changesUnion.pageSQL): exact only while a repeatable branch is
			// deduplicated before its cut and every branch honours the
			// cursor. A branch that returned the same event twice would fill
			// its limit+1 rows with fewer events, and a page would end early
			// (no next_cursor) or skip one.
			want := make([]string, 0, len(all))
			for _, e := range all {
				want = append(want, digs(e, "id"))
			}
			for _, limit := range []int{1, 2, 3} {
				if got := loadChangesPaged(t, api, c.refType, c.id, limit); strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("limit %d pages list %d events %v, the limit-200 list %d %v", limit, len(got), got, len(want), want)
				}
			}
		})
	}
}

// loadChangesPaged reads every configuration page of an object's Changes at
// one limit and returns the event ids in order.
func loadChangesPaged(t *testing.T, api *readAPI, refType string, id uuid.UUID, limit int) []string {
	t.Helper()
	var out []string
	cursor := ""
	for page := 0; page < 500; page++ {
		kv := []string{"limit", strconv.Itoa(limit)}
		if cursor != "" {
			kv = append(kv, "cursor", cursor)
		}
		body := changesGet(t, api, changesPath(refType, id, kv...))
		for _, e := range digl(body, "data") {
			out = append(out, digs(e, "id"))
		}
		if cursor = digs(body, "meta", "next_cursor"); cursor == "" {
			return out
		}
	}
	t.Fatalf("Changes of %s %s at limit %d did not end within 500 pages", refType, id, limit)
	return nil
}
