package igaread

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RequestBudget is the ONE deadline for a whole read request (§5.1). Every
// query of the request runs under it, and the driver cancels the in-flight
// statement when it passes. statement_timeout alone cannot do this: it bounds
// each statement separately, so ten statements could each take the full
// allowance.
const RequestBudget = 3 * time.Second

// Revision is one workspace publication (033): rev names exactly one committed
// state of the workspace's graph.
type Revision struct {
	Rev         int64
	PublishedAt time.Time
}

// snapshotSettingsSQL makes every statement of the snapshot plan with its own
// bind values (§5.6). The driver (pgx) prepares and caches each statement per
// connection, and after five executions PostgreSQL may switch a prepared
// statement to a GENERIC plan, costed without the values. Graph reads are
// parameterised by one object in a skewed estate -- "*" is named by a quarter
// of all statements, one execution role backs hundreds of workloads -- so a
// generic plan is chosen for the typical object and is ruinous for the hot
// one: T6.10 measured the Changes page of "*" at 0.5 s with a custom plan and
// over 20 s with the generic one, so every sixth request on a connection
// answered 504 (a timed-out request closes its connection, and the count
// starts again). Planning a statement costs well under a millisecond to a few
// milliseconds; the snapshot's reads are never hot loops of one statement.
// SET LOCAL ends with the transaction, so the pool's connections are left as
// they were for everything else.
//
// The same statement turns JIT compilation off for the snapshot. PostgreSQL
// JIT-compiles any statement whose estimated cost passes jit_above_cost
// (100 000 by default), and compiling costs hundreds of milliseconds before the
// first row: T6.10 measured a holder count over "*" at 106 ms without JIT and
// 875 ms with it. A read's estimate crosses the threshold on size alone -- the
// resource list's page is costed at 75 000 on the 10 000-object fixture -- so
// a slightly larger estate would pay it on every request, inside a 3 s budget,
// for statements that run for tens of milliseconds. set_config(..., true) is
// SET LOCAL; one round trip sets both.
const snapshotSettingsSQL = "SELECT set_config('plan_cache_mode', 'force_custom_plan', true), set_config('jit', 'off', true)"

// Reader is the only way to read the graph (§5.1).
type Reader struct {
	db        *gorm.DB
	budget    time.Duration
	cursorKey []byte
	// accessDenseAt is where Resource › Access switches to finding its page
	// of holders identity-first (rdetailAccessDenseAt).
	accessDenseAt int
}

// NewReader builds a reader over db. cursorKey signs list cursors
// (IGA_CURSOR_SECRET); it must be the same on every replica.
func NewReader(db *gorm.DB, cursorKey []byte) *Reader {
	installGraphWiden(db)
	return &Reader{db: db, budget: RequestBudget, cursorKey: cursorKey, accessDenseAt: rdetailAccessDenseAt}
}

// WithBudget returns a copy with a different request budget. Tests use it to
// make the deadline bind; production uses RequestBudget.
func (r *Reader) WithBudget(d time.Duration) *Reader {
	cp := *r
	cp.budget = d
	return &cp
}

// Budget is the request deadline this reader applies.
func (r *Reader) Budget() time.Duration { return r.budget }

// WithAccessDenseAt returns a copy whose Resource › Access pages holders
// identity-first from n positive targets on (rdetailAccessDenseAt). The two
// strategies return the same rows in the same order; tests use this to run
// both over one estate. Production uses the default.
func (r *Reader) WithAccessDenseAt(n int) *Reader {
	cp := *r
	cp.accessDenseAt = n
	return &cp
}

// Pin is what the request asked to be pinned to: the rev parameter, and the
// revision the presented cursor was issued at. Either may be nil.
type Pin struct {
	Rev       *int64
	CursorRev *int64
}

// Query is one request's snapshot. Every query of the request goes through
// DB() (mandatory) or Optional (work whose absence the response can state).
type Query struct {
	tx       *gorm.DB
	ctx      context.Context
	deadline time.Time
	// WS is the workspace from the token; every query filters on it.
	WS uuid.UUID
	// Rev is the revision the request reads; nil when nothing is published.
	Rev *Revision
	// V2 is graph=v2. Providers is the closed set the snapshot may read.
	// Both stay zero on a default request, and SQL() is then an identity.
	V2        bool
	Providers []string

	savepoints int
	baseMS     int64
}

// Read runs fn inside ONE read-only REPEATABLE READ snapshot under ONE
// deadline, after checking the pinned revision (§5.1).
//
// Because the revision check and every data query share the snapshot, and a
// publication commits atomically with its graph, a response cannot straddle
// two publications.
func (r *Reader) Read(ctx context.Context, ws uuid.UUID, pin Pin, fn func(q *Query) error) error {
	ctx, cancel := context.WithTimeout(ctx, r.budget)
	defer cancel()
	deadline, _ := ctx.Deadline()

	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Backstop per statement: never longer than the whole budget. Optional
		// work lowers it locally inside a savepoint and restores it after.
		base := r.budget.Milliseconds()
		if err := tx.Exec(fmt.Sprintf("SET LOCAL statement_timeout = %d", base)).Error; err != nil {
			return err
		}
		// Custom plans only, no JIT (snapshotSettingsSQL).
		if err := tx.Exec(snapshotSettingsSQL).Error; err != nil {
			return err
		}
		cur, err := currentRevision(tx, ws)
		if err != nil {
			return err
		}
		for _, want := range []*int64{pin.Rev, pin.CursorRev} {
			if want != nil && (cur == nil || cur.Rev != *want) {
				return RevisionStale(*want, cur)
			}
		}
		sc := graphScopeFrom(ctx)
		q := &Query{
			tx: tx, ctx: ctx, deadline: deadline, WS: ws, Rev: cur, baseMS: base,
			V2: sc.V2, Providers: sc.Providers,
		}
		return fn(q)
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err == nil {
		return nil
	}
	// A deadline that passed inside fn surfaces as whatever the driver said;
	// the context is the authority on whether it was time.
	var ce *Error
	if !errors.As(err, &ce) && ctx.Err() != nil {
		return QueryTimeout(err)
	}
	return AsError(err)
}

func currentRevision(tx *gorm.DB, ws uuid.UUID) (*Revision, error) {
	var rows []struct {
		Rev         int64
		PublishedAt time.Time
	}
	if err := tx.Raw(`SELECT rev, published_at FROM iga_publication
		WHERE workspace_id = ? ORDER BY rev DESC LIMIT 1`, ws).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &Revision{Rev: rows[0].Rev, PublishedAt: rows[0].PublishedAt}, nil
}

// DB is the snapshot's transaction for MANDATORY queries: an error or timeout
// fails the whole request (500 / 504), nothing partial.
func (q *Query) DB() *gorm.DB { return q.tx }

// Context is the request context, carrying the deadline.
func (q *Query) Context() context.Context { return q.ctx }

// Deadline is when the request budget ends.
func (q *Query) Deadline() time.Time { return q.deadline }

// Remaining is the budget left, never negative.
func (q *Query) Remaining() time.Duration {
	d := time.Until(q.deadline)
	if d < 0 {
		return 0
	}
	return d
}

// Published reports whether the workspace has any publication. When false the
// response is 200 with empty data and meta.graph_state = "not_published".
func (q *Query) Published() bool { return q.Rev != nil }

// ErrNoTime is returned by Optional when too little budget remains to try the
// work at all. Callers treat it exactly like a timeout: the value is unknown.
var ErrNoTime = errors.New("igaread: request budget exhausted")

// minOptional is the least time worth giving optional work; below it the work
// is reported unknown without running.
const minOptional = 20 * time.Millisecond

// Optional runs work whose absence the response can state honestly (a total,
// a facet, a neighbour count, one traversal level) inside a SAVEPOINT, with a
// local statement timeout of at most half the remaining budget (§5.1).
//
// ok=false, err=nil: it timed out (or there was no time to try), the savepoint
// was rolled back, and the transaction continues in the same snapshot -- the
// caller reports the value as unknown. err!=nil: any other database error,
// which fails the request (500).
//
// Without the savepoint a timed-out statement aborts the whole transaction and
// every later query fails. The SET LOCAL made inside the savepoint is undone by
// ROLLBACK TO SAVEPOINT; on success it is restored explicitly, because RELEASE
// keeps it.
func (q *Query) Optional(fn func(tx *gorm.DB) error) (bool, error) {
	allow := q.Remaining() / 2
	if allow < minOptional {
		return false, nil
	}
	q.savepoints++
	sp := fmt.Sprintf("igaread_sp_%d", q.savepoints)
	if err := q.tx.Exec("SAVEPOINT " + sp).Error; err != nil {
		return false, err
	}
	if err := q.tx.Exec(fmt.Sprintf("SET LOCAL statement_timeout = %d", allow.Milliseconds())).Error; err != nil {
		return false, err
	}
	ferr := fn(q.tx)
	if ferr != nil {
		if q.ctx.Err() != nil {
			// The whole request deadline passed: the connection's statement was
			// cancelled and the transaction cannot be rolled back to anything.
			return false, QueryTimeout(ferr)
		}
		if rerr := q.tx.Exec("ROLLBACK TO SAVEPOINT " + sp).Error; rerr != nil {
			return false, rerr
		}
		if IsTimeout(ferr) {
			return false, nil
		}
		return false, ferr
	}
	if err := q.tx.Exec("RELEASE SAVEPOINT " + sp).Error; err != nil {
		return false, err
	}
	if err := q.tx.Exec(fmt.Sprintf("SET LOCAL statement_timeout = %d", q.baseMS)).Error; err != nil {
		return false, err
	}
	return true, nil
}
