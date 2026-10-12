package services

import (
	"context"
	"hash/fnv"
	"log"

	"gorm.io/gorm"
)

// RunAsLeader runs fn only if this replica holds the Postgres advisory lock
// for name, so periodic jobs run once across replicas instead of once per
// replica (duplicate Hydra calls and reminder emails, AS-037). The lock is
// session-level on a dedicated connection and released when fn returns.
func RunAsLeader(ctx context.Context, db *gorm.DB, name string, fn func()) {
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("[leader] %s: no database handle: %v", name, err)
		return
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		log.Printf("[leader] %s: no connection: %v", name, err)
		return
	}
	defer conn.Close()

	h := fnv.New64a()
	_, _ = h.Write([]byte("authsec-job:" + name))
	key := int64(h.Sum64())

	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil || !got {
		return // another replica is running it
	}
	defer func() {
		if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
			log.Printf("[leader] %s: unlock failed: %v", name, err)
		}
	}()
	fn()
}
