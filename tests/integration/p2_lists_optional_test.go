package integration

// §5.1 "What each kind of read does when time or the database fails", for the
// lists (B23): an OPTIONAL count that times out is reported unknown and the
// page is still returned; nothing is guessed.
//
// A real statement timeout, with no hook in production code: another session
// holds an ACCESS EXCLUSIVE lock on the one table only the optional count
// reads. The count waits on the lock until its savepoint's statement_timeout
// (half the remaining budget) cancels it; the page, which never touches that
// table, is unaffected.

import (
	"context"
	"net/url"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// listsWithTableLocked runs fn while another transaction holds table ACCESS
// EXCLUSIVE, then releases it.
func listsWithTableLocked(t *testing.T, db *gorm.DB, table string, fn func()) {
	t.Helper()
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin: %v", tx.Error)
	}
	defer tx.Rollback()
	if err := tx.Exec(`LOCK TABLE ` + table + ` IN ACCESS EXCLUSIVE MODE`).Error; err != nil {
		t.Fatalf("lock %s: %v", table, err)
	}
	fn()
}

func TestP2ListsOptionalCountTimesOutPageStillReturned(t *testing.T) {
	l := newP2Lab(t, "p2-lists-optional", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	listsFunctions(a, "us-east-1", "t1", role, "t2", role)
	l.scanAndProject(a)
	api := l.api()

	// used_by_count reads only iga_relationship.
	listsWithTableLocked(t, l.db, "iga_relationship", func() {
		start := time.Now()
		body := listsGet(t, api, "/identities")
		rows := digl(body, "data")
		if len(rows) != 1 || digs(rows[0], "name") != "SharedToolRole" {
			t.Fatalf("page = %v, want the identity row despite the timed-out count", rows)
		}
		if v := dig(rows[0], "used_by_count", "value"); v != nil || dig(rows[0], "used_by_count", "exact") != false {
			t.Errorf("used_by_count = %v, want {value: null, exact: false} -- never a number that looks exact", dig(rows[0], "used_by_count"))
		}
		if dig(body, "meta", "total_known") != true || num(body, "meta", "total") != 1 {
			t.Errorf("meta = %v: the total does not read the locked table and must still be known", body["meta"])
		}
		if el := time.Since(start); el < igaread.RequestBudget/4 || el > igaread.RequestBudget {
			t.Errorf("request took %s: the count did not wait on the lock and time out inside the budget", el)
		}
	})
	// With the lock gone the same count is exact again.
	if r := digl(listsGet(t, api, "/identities"), "data"); num(r[0], "used_by_count", "value") != 2 {
		t.Errorf("used_by_count without the lock = %v, want 2", dig(r[0], "used_by_count"))
	}

	// named_by_count / excluded_by_count read only iga_entitlement_target.
	listsWithTableLocked(t, l.db, "iga_entitlement_target", func() {
		rows := digl(listsGet(t, api, "/resources"), "data")
		if len(rows) != 1 || digs(rows[0], "text") != "arn:aws:s3:::support-tickets/*" {
			t.Fatalf("page = %v, want the resource row", rows)
		}
		for _, c := range []string{"named_by_count", "excluded_by_count"} {
			if dig(rows[0], c, "value") != nil || dig(rows[0], c, "exact") != false {
				t.Errorf("%s = %v, want {value: null, exact: false}", c, dig(rows[0], c))
			}
		}
	})
}

// A budget too small for any optional work: Optional reports unknown without
// running (half of what remains is under its floor), so totals are not known
// and every requested facet is null -- while the mandatory page is served.
//
// Only the mandatory statements must fit the budget; a machine too loaded for
// them answers 504, which is the contract too, so that outcome is retried.
func TestP2ListsNoTimeForOptionalWork(t *testing.T) {
	l := newP2Lab(t, "p2-lists-notime", true)
	l.scanAndProject(oneLambda(l))
	r := igaread.NewReader(l.db, readTestCursorKey).WithBudget(39 * time.Millisecond)

	var res any
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		res, err = r.ListWorkloads(context.Background(), l.ws, url.Values{"facets": {"account,region"}})
		if e := igaread.AsError(err); e == nil || e.Code != "query_timeout" {
			break
		}
	}
	if err != nil {
		t.Fatalf("list under a tiny budget: %v", err)
	}
	env := res.(igaread.Envelope)
	meta := env.Meta.(igaread.ListMeta)
	if rows := env.Data.([]igaread.WorkloadRow); len(rows) != 1 {
		t.Fatalf("page = %v, want the one workload", rows)
	}
	if meta.TotalKnown || meta.Total != nil || meta.TotalAtLeast != nil {
		t.Errorf("totals = known %v total %v at least %v, want unknown and never guessed", meta.TotalKnown, meta.Total, meta.TotalAtLeast)
	}
	for _, name := range []string{"account", "region"} {
		if vals, present := meta.Facets[name]; !present || vals != nil {
			t.Errorf("facet %s = %v (present %v), want null", name, vals, present)
		}
	}
}

// CountUpTo is optional work: a count that times out is known=false, no error,
// and the snapshot goes on.
func TestP2ListsCountUpToTimesOut(t *testing.T) {
	l := newP2Lab(t, "p2-lists-countupto", true)
	l.scanAndProject(oneLambda(l))
	r := igaread.NewReader(l.db, readTestCursorKey).WithBudget(800 * time.Millisecond)
	err := r.Read(context.Background(), l.ws, igaread.Pin{}, func(q *igaread.Query) error {
		n, known, err := q.CountUpTo(func(tx *gorm.DB) *gorm.DB { return tx.Table("(SELECT pg_sleep(2)) AS s") })
		if err != nil || known || n != 0 {
			t.Fatalf("CountUpTo past its allowance = %d known=%v err=%v, want unknown with no error", n, known, err)
		}
		n, known, err = q.CountUpTo(func(tx *gorm.DB) *gorm.DB {
			return tx.Table("iga_workload").Where("workspace_id = ?", q.WS)
		})
		if err != nil || !known || n != 1 {
			t.Fatalf("a count after the timed-out one = %d known=%v err=%v, want 1 in the same snapshot", n, known, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
