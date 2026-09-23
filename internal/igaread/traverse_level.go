package igaread

// One traversal level's time allowance (§5.1 "Each level's query runs in a
// savepoint, so a level that times out is rolled back and the previous levels
// are returned"; D-40, B23).
//
// A level runs inside Query.Optional, whose savepoint sets ONE
// statement_timeout -- but a level is a dozen statements, and some of them are
// shared readers that issue several statements of their own (NodeStaleReasons,
// Query.Coverage) and nest an Optional of their own, whose allowance is half
// of the REQUEST's remaining budget and whose RELEASE puts the request's base
// timeout back. Statements each allowed a stale allowance could together run
// past the request deadline, and the request would fail (504) instead of the
// level being truncated. So the level hands out a Query whose every statement
// -- the traversal's own and the shared readers' alike -- is re-armed, just
// before it runs, with what is LEFT of the level's allowance, and whose
// Remaining() is the level's, so a nested Optional's allowance (half of what
// remains) fits inside it and leaves the rest of the level its half.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// graphLevel bounds one level's statements. The zero deadline is the
// mandatory root read: the request's own backstop applies.
type graphLevel struct {
	q        *Query
	deadline time.Time
	lq       *Query // the level's re-arming query, built on first use
}

// graphErrLevelTime is a level that used its whole allowance. It is a timeout
// (IsTimeout), so Optional rolls the level back and reports it not done.
var graphErrLevelTime = fmt.Errorf("igaread: traversal level out of time: %w", context.DeadlineExceeded)

func (t *graphTraversal) mandatory() *graphLevel { return &graphLevel{q: t.q} }

// optionalLevel starts a level inside Optional's savepoint: its allowance is
// the half of the remaining budget Optional gave it.
func (t *graphTraversal) optionalLevel() *graphLevel {
	return &graphLevel{q: t.q, deadline: time.Now().Add(t.q.Remaining() / 2)}
}

// query is the Query the level's statements run through: the request's own
// for the mandatory root read, else a copy of it in the same transaction and
// snapshot whose statements are each re-armed to the level's remaining
// allowance and whose deadline is the level's (graphArmedPool).
func (lv *graphLevel) query() *Query {
	if lv.deadline.IsZero() {
		return lv.q
	}
	if lv.lq == nil {
		// Session with a Context clones the Statement, so replacing its
		// ConnPool leaves the request's own handle untouched.
		tx := lv.q.tx.Session(&gorm.Session{Context: lv.q.ctx})
		tx.Statement.ConnPool = &graphArmedPool{ConnPool: tx.Statement.ConnPool, deadline: lv.deadline}
		cp := *lv.q
		cp.tx, cp.deadline = tx, lv.deadline
		lv.lq = &cp
	}
	return lv.lq
}

// db is the handle for the level's next statement, or graphErrLevelTime when
// the allowance is spent (so the level stops before issuing it).
func (lv *graphLevel) db() (*gorm.DB, error) {
	if lv.deadline.IsZero() {
		return lv.q.DB(), nil
	}
	if time.Until(lv.deadline) < time.Millisecond {
		return nil, graphErrLevelTime
	}
	return lv.query().DB(), nil
}

// done hands the savepoint numbering back to the request's Query: a nested
// Optional on the level's copy advanced the copy's counter, and the request's
// next savepoint must not reuse a name.
func (lv *graphLevel) done() {
	if lv.lq != nil && lv.lq.savepoints > lv.q.savepoints {
		lv.q.savepoints = lv.lq.savepoints
	}
}

// graphArmedPool runs every statement of a level after `SET LOCAL
// statement_timeout` to what is left of the level's allowance (at least 1 ms:
// 0 would disable the timeout) -- except inside a NESTED savepoint. A nested
// Optional (a shared reader's optional history walk) sets its own timeout, of
// half the level's remaining time (the copy's Remaining() is the level's), so
// it already fits the level; re-arming its statements to the whole remainder
// would take away the half it leaves for the rest of the level. The depth is
// read off the savepoint commands passing through, which in this package only
// Optional issues. After the nested savepoint is released (and Optional puts
// the request's base timeout back) or rolled back, the next statement is
// re-armed again.
type graphArmedPool struct {
	gorm.ConnPool
	deadline time.Time
	depth    int // nested savepoints open on the level's query
}

func (p *graphArmedPool) arm(ctx context.Context, query string) error {
	nested := p.depth > 0
	switch q := strings.TrimSpace(query); {
	case strings.HasPrefix(q, "SAVEPOINT "):
		p.depth++
	case strings.HasPrefix(q, "RELEASE SAVEPOINT "), strings.HasPrefix(q, "ROLLBACK TO SAVEPOINT "):
		// Optional never continues inside a savepoint it rolled back to.
		if p.depth > 0 {
			p.depth--
		}
	}
	if nested {
		return nil
	}
	ms := time.Until(p.deadline).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	_, err := p.ConnPool.ExecContext(ctx, fmt.Sprintf("SET LOCAL statement_timeout = %d", ms))
	return err
}

func (p *graphArmedPool) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if err := p.arm(ctx, query); err != nil {
		return nil, err
	}
	return p.ConnPool.ExecContext(ctx, query, args...)
}

func (p *graphArmedPool) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if err := p.arm(ctx, query); err != nil {
		return nil, err
	}
	return p.ConnPool.QueryContext(ctx, query, args...)
}

// QueryRowContext cannot return an error of its own: a failed arm leaves the
// transaction failed, and the row's Scan reports it.
func (p *graphArmedPool) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	_ = p.arm(ctx, query)
	return p.ConnPool.QueryRowContext(ctx, query, args...)
}
