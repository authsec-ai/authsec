package integration

// T6.4, §5.1 and D-40 through the real traversal: a level's shared readers --
// NodeStaleReasons for a stale node, the stale-edge run history, and the far
// account's Query.Coverage -- each open an Optional of their own INSIDE the
// level's savepoint. That nested Optional must be given half of what is left
// of the LEVEL's allowance, never half of the request's: a nested allowance
// larger than the level's could run past the request deadline and fail the
// request (504) instead of truncating the level (B23).
//
// The SQL is recorded through a gorm logger on the reader's handle: every
// SAVEPOINT and the `SET LOCAL statement_timeout` Optional issues right after
// it. A nested SAVEPOINT's timeout must be at most half its enclosing level's.

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// graphSQLRecorder is a gorm logger that keeps every statement, in order.
type graphSQLRecorder struct {
	mu  sync.Mutex
	sql []string
}

func (r *graphSQLRecorder) LogMode(logger.LogLevel) logger.Interface { return r }
func (r *graphSQLRecorder) Info(context.Context, string, ...any)     {}
func (r *graphSQLRecorder) Warn(context.Context, string, ...any)     {}
func (r *graphSQLRecorder) Error(context.Context, string, ...any)    {}
func (r *graphSQLRecorder) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	s, _ := fc()
	r.mu.Lock()
	r.sql = append(r.sql, strings.TrimSpace(s))
	r.mu.Unlock()
}

var graphTimeoutSQL = regexp.MustCompile(`^SET LOCAL statement_timeout = (\d+)$`)

// graphNestedTimeouts runs one request through a recording reader and returns,
// for every savepoint opened inside another, its timeout and its parent's.
func graphNestedTimeouts(t *testing.T, l *p2Lab, route string, kv ...string) [][2]int64 {
	t.Helper()
	rec := &graphSQLRecorder{}
	r := igaread.NewReader(l.db.Session(&gorm.Session{Logger: rec}), readTestCursorKey)
	code, body := graphDirect(t, r, igaread.DefaultGraphBudgets, l.ws, route, kv...)
	mustStatus(t, route, code, body, 200)
	if body["data"].(map[string]any)["truncated"] != nil {
		t.Fatalf("setup: %s truncated %v -- the check needs levels that ran", route, dig(body, "data", "truncated"))
	}
	var stack []int64 // the open savepoints' timeouts
	var nested [][2]int64
	openedAt := -1
	for i, s := range rec.sql {
		switch {
		case strings.HasPrefix(s, "SAVEPOINT "):
			stack = append(stack, -1)
			openedAt = i
		case strings.HasPrefix(s, "RELEASE SAVEPOINT "), strings.HasPrefix(s, "ROLLBACK TO SAVEPOINT "):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			if m := graphTimeoutSQL.FindStringSubmatch(s); m != nil && openedAt == i-1 && len(stack) > 0 {
				ms, _ := strconv.ParseInt(m[1], 10, 64)
				stack[len(stack)-1] = ms
				if len(stack) > 1 {
					nested = append(nested, [2]int64{ms, stack[len(stack)-2]})
				}
			}
		}
	}
	return nested
}

func graphCheckNested(t *testing.T, name string, nested [][2]int64) {
	t.Helper()
	if len(nested) == 0 {
		t.Fatalf("%s: no nested optional was recorded -- the fixture does not exercise the shared readers", name)
	}
	for _, n := range nested {
		// Optional gives half of Remaining(); the level's copy says the
		// level's remaining time, which is at most its allowance.
		if n[1] < 0 || n[0] > n[1]/2+1 {
			t.Errorf("%s: a nested optional was given %d ms inside a level allowed %d ms, want at most half", name, n[0], n[1])
		}
	}
}

func TestP2GraphNestedOptionalsFitTheirLevel(t *testing.T) {
	// A stale role and stale edges: NodeStaleReasons' history walk and the
	// edges' run history run inside the level that reaches them.
	l := newP2Lab(t, "p2-graph-nested-stale", true)
	a := graphTeaching(t, l)
	l.scanAndProject(a)
	a.iam.fail["GetAccountAuthorizationDetails:Role"] = denied("iam:GetAccountAuthorizationDetails")
	l.scanAndProject(a)
	graphCheckNested(t, "stale", graphNestedTimeouts(t, l, "/graph", "root", graphWorkload(t, l, "ticket-tools"), "direction", "forward"))
}

// A crossing edge into a connected account: the far account's coverage
// (Query.Coverage and its optional since walk) is read inside the level.
func TestP2GraphNestedCoverageFitsItsLevel(t *testing.T) {
	x := newP2Lab(t, "p2-graph-nested-cross", true)
	b := x.account(accountB)
	b.role("data-reader", "AROADATAREADERNESTED")
	trustCycle(x, b, nil)
	ac := x.account(accountA)
	trustRole(ac, "reader-access", "AROAREADERACCESSNEST", trustDoc(trustAllow(`{"AWS":"arn:aws:iam::`+accountB+`:role/data-reader"}`, "sts:AssumeRole")))
	trustCycle(x, ac, nil)
	graphCheckNested(t, "cross", graphNestedTimeouts(t, x, "/graph", "root", graphIdentity(t, x, "data-reader"), "direction", "forward"))
}
