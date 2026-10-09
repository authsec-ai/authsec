// Command bootstrap-parity applies a directory of master migrations to one
// database with the REAL runner (internal/migration), exactly as cmd/main.go
// does on boot: GORM AutoMigrate creates migration_logs, then
// MasterMigrationRunner applies each pending file in version order, one
// transaction per file, recording each in migration_logs.
//
// It exists only so scripts/bootstrap-parity-check.sh rehearses migrations
// through the same statement splitter, transaction boundary and session reuse
// as production, rather than through psql, which differs on all three.
//
//	go run ./scripts/bootstrap-parity -dsn "host=... dbname=p3b_x ..." -dir /path/to/master
//
// -rerun deletes the migration_logs rows of the files in -dir first, so the
// runner executes them again; it is how the check proves the later files are
// re-runnable. Never point it at a database you care about.
package main

import (
	"database/sql"
	"flag"
	"log"
	"os"

	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/internal/migration"
)

func main() {
	dsn := flag.String("dsn", "", "libpq key=value DSN of the scratch database")
	dir := flag.String("dir", "", "directory of NNN_name.sql files to apply")
	rerun := flag.Bool("rerun", false, "forget the files in -dir in migration_logs first, so they execute again")
	flag.Parse()
	if *dsn == "" || *dir == "" {
		flag.Usage()
		os.Exit(2)
	}

	rawDB, err := sql.Open("postgres", *dsn)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer rawDB.Close()
	gormDB, err := gorm.Open(postgres.Open(*dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		log.Fatalf("gorm open: %v", err)
	}
	if err := migration.AutoMigrateMigrationLogs(gormDB); err != nil {
		log.Fatalf("auto-migrate migration_logs: %v", err)
	}

	runner := migration.NewMasterMigrationRunner(*dir, rawDB, gormDB)
	if *rerun {
		files, err := runner.LoadMigrationFiles()
		if err != nil {
			log.Fatalf("load: %v", err)
		}
		for _, f := range files {
			if _, err := rawDB.Exec(`DELETE FROM migration_logs WHERE version = $1 AND name = $2 AND db_type = 'master'`, f.Version, f.Name); err != nil {
				log.Fatalf("forget v%d: %v", f.Version, err)
			}
		}
	}
	if err := runner.RunMigrations(); err != nil {
		log.Fatalf("run: %v", err)
	}
	var failed int
	if err := rawDB.QueryRow(`SELECT count(*) FROM migration_logs WHERE success = false`).Scan(&failed); err != nil {
		log.Fatalf("count failures: %v", err)
	}
	if failed > 0 {
		log.Fatalf("%d failed rows in migration_logs", failed)
	}
}
