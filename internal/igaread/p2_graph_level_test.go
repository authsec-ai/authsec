package igaread

// A traversal level's allowance, against real PostgreSQL (§5.1, D-40, B23):
// every statement run through a level's query -- the traversal's own and the
// shared readers' (NodeStaleReasons, Query.Coverage) with their nested
// Optional -- is re-armed to what is LEFT of the level's allowance. Without
// that, statements each given the allowance at the level's start could
// together run past the request deadline, and a request that should be 200
// truncated time would fail 504.
//
// pg_sleep stands in for a slow statement: the mechanism is the subject here,
// and no fixture makes a shared reader's third statement slow on demand. The
// traversal's own time behaviour is tested end to end in
// tests/integration/p2_graph_budgets_test.go. Skips without IGA_TEST_DSN.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func graphLevelReader(t *testing.T) *Reader {
	t.Helper()
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set; skipping the database-backed level test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	sqlDB.SetMaxOpenConns(2)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return NewReader(db, []byte("graph-level-test-key"))
}

// graphLevelRead runs fn as one optional level inside a request snapshot, as
// runLevel does, with the given allowance.
func graphLevelRead(t *testing.T, r *Reader, allowance time.Duration, fn func(q *Query, lv *graphLevel) error) (bool, *Query) {
	t.Helper()
	var ok bool
	var held *Query
	err := r.Read(context.Background(), uuid.New(), Pin{}, func(q *Query) error {
		held = q
		var lv *graphLevel
		var err error
		ok, err = q.Optional(func(*gorm.DB) error {
			lv = &graphLevel{q: q, deadline: time.Now().Add(allowance)}
			return fn(q, lv)
		})
		if lv != nil {
			lv.done()
		}
		if err != nil {
			return err
		}
		// The transaction is still usable: a rolled-back level leaves it so.
		var one int
		return q.DB().Raw(`SELECT 1`).Row().Scan(&one)
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return ok, held
}

func TestP2GraphLevelRearmsEveryStatement(t *testing.T) {
	r := graphLevelReader(t)

	// Two statements through the level's query. The first spends 200 ms of a
	// 300 ms allowance; the second must be cut at what is LEFT (~100 ms), not
	// given a fresh 300 ms -- nor the 1.5 s the enclosing savepoint allows.
	var second error
	start := time.Now()
	ok, _ := graphLevelRead(t, r, 300*time.Millisecond, func(q *Query, lv *graphLevel) error {
		if err := lv.query().DB().Exec(`SELECT pg_sleep(0.2)`).Error; err != nil {
			return err
		}
		second = lv.query().DB().Exec(`SELECT pg_sleep(0.4)`).Error
		return second
	})
	elapsed := time.Since(start)
	if ok || !IsTimeout(second) {
		t.Errorf("second statement: level ok=%v err=%v, want a timeout at the end of the level's allowance", ok, second)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("the level took %s, past its 300 ms allowance", elapsed)
	}

	// A shared reader's nested Optional through the level's query is held to
	// the level: its allowance is half of the LEVEL's remaining time (~200
	// ms) -- not half of the request's (~1.5 s), and not the level's whole
	// remainder (~400 ms), which would leave the rest of the level nothing.
	var nestedOK bool
	var nested time.Duration
	ok, q := graphLevelRead(t, r, 400*time.Millisecond, func(q *Query, lv *graphLevel) error {
		t0 := time.Now()
		var err error
		nestedOK, err = lv.query().Optional(func(tx *gorm.DB) error {
			return tx.Exec(`SELECT pg_sleep(1)`).Error
		})
		nested = time.Since(t0)
		if err != nil {
			return err
		}
		// And after its RELEASE put the request's base timeout back, the
		// level's next statement is still re-armed to the level.
		return lv.query().DB().Exec(`SELECT pg_sleep(0.6)`).Error
	})
	if nestedOK || nested > 300*time.Millisecond {
		t.Errorf("nested optional: ok=%v after %s, want it cut at half the level's remaining allowance", nestedOK, nested)
	}
	if ok {
		t.Errorf("the level's statement after the nested optional ran past the level's allowance")
	}
	// The request's savepoint numbering moved past the nested one.
	if q.savepoints < 2 {
		t.Errorf("savepoints = %d, want the nested savepoint counted on the request's query", q.savepoints)
	}

	// Control: statements that fit the allowance run, and the level succeeds.
	ok, _ = graphLevelRead(t, r, time.Second, func(q *Query, lv *graphLevel) error {
		for i := 0; i < 3; i++ {
			if err := lv.query().DB().Exec(`SELECT pg_sleep(0.05)`).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if !ok {
		t.Errorf("control: a level within its allowance was cut")
	}
}
