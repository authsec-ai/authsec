package igagovschema_test

// T3.02, schema verification only: VerifyPolicySchema accepts the 056 schema
// and refuses one that lacks ANY single Phase 3 relation, naming it. (The 046
// refusal is in TestPhase3UpgradeOverExistingRows.) The IGA_POLICY gate,
// routes and capabilities are later T3.02 work and are not exercised here.

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/services"
)

var errRollback = errors.New("rollback")

func TestVerifyPolicySchemaAt056(t *testing.T) {
	_, g := testDB(t)
	if err := services.VerifyPolicySchema(g); err != nil {
		t.Fatalf("VerifyPolicySchema at 056: %v", err)
	}
}

// Every relation, one at a time, dropped inside a transaction that is rolled
// back: verification must fail and name exactly what is missing.
func TestVerifyPolicySchemaFailsWhenOneIsMissing(t *testing.T) {
	_, g := testDB(t)
	rels := services.PolicySchemaRelations()
	if len(rels) < 60 {
		t.Fatalf("only %d relations verified; 047-056 create 43 tables, a sequence and 19 named indexes", len(rels))
	}
	for _, rel := range rels {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			err := g.Transaction(func(tx *gorm.DB) error {
				var kind string
				if err := tx.Raw(`SELECT relkind::text FROM pg_class WHERE oid = to_regclass(?)`, "public."+rel).Scan(&kind).Error; err != nil {
					return err
				}
				var drop string
				switch kind {
				case "r":
					drop = "DROP TABLE " + rel + " CASCADE"
				case "i":
					drop = "DROP INDEX " + rel
				case "S": // an identity sequence goes only with its identity
					drop = "ALTER TABLE iga_gov_event ALTER COLUMN id DROP IDENTITY"
				default:
					t.Fatalf("%s: unexpected relkind %q", rel, kind)
				}
				if err := tx.Exec(drop).Error; err != nil {
					return err
				}
				verr := services.VerifyPolicySchema(tx)
				if verr == nil {
					t.Errorf("verification passed without %s", rel)
				} else if !strings.Contains(verr.Error(), "missing: ") || !containsName(verr.Error(), rel) {
					t.Errorf("verification without %s did not name it: %v", rel, verr)
				}
				return errRollback
			})
			if !errors.Is(err, errRollback) {
				t.Fatalf("%s: %v", rel, err)
			}
		})
	}
	if err := services.VerifyPolicySchema(g); err != nil {
		t.Fatalf("schema not restored after the rollbacks: %v", err)
	}
}

func containsName(msg, name string) bool {
	_, list, _ := strings.Cut(msg, "missing: ")
	for _, n := range strings.Split(list, ", ") {
		if n == name {
			return true
		}
	}
	return false
}

// p3-wire: the notification channel columns of 055's iga_gov_settings are
// checked by name -- a database built from 055's first draft has the table
// without them -- and each missing one is named.
func TestVerifyPolicySchemaFailsWithoutAChannelColumn(t *testing.T) {
	_, g := testDB(t)
	cols := services.PolicySchemaColumns()
	if len(cols) != 5 {
		t.Fatalf("channel columns checked: %v", cols)
	}
	for _, qc := range cols {
		qc := qc
		t.Run(qc, func(t *testing.T) {
			table, col, _ := strings.Cut(qc, ".")
			err := g.Transaction(func(tx *gorm.DB) error {
				if err := tx.Exec("ALTER TABLE " + table + " DROP COLUMN " + col).Error; err != nil {
					return err
				}
				verr := services.VerifyPolicySchema(tx)
				if verr == nil || !containsName(verr.Error(), qc) {
					t.Errorf("verification without %s: %v", qc, verr)
				}
				return errRollback
			})
			if !errors.Is(err, errRollback) {
				t.Fatalf("%s: %v", qc, err)
			}
		})
	}
}

// A name VerifyPolicySchema checks that the database does not have keeps the
// gate permanently unverified, and Postgres silently truncates a longer name
// at 63 bytes (so a constraint named in full never exists under it). Every
// relation, trigger and constraint the gate names must therefore fit in an
// identifier AND exist in a database built from 001_bootstrap.sql alone -- the
// fresh-install path, which the migration-built database of the other tests
// does not prove.
//
// Unnamed single-column enum CHECKs are not checked: they have no stable name
// to look up, and matching their expression text would restate the DDL.
func TestVerifyPolicySchemaNamesExistInAFreshBootstrap(t *testing.T) {
	_, g := testDB(t)

	for _, group := range []struct {
		kind  string
		names []string
	}{
		{"relation", services.PolicySchemaRelations()},
		{"trigger", services.PolicySchemaTriggers()},
		{"constraint", services.PolicySchemaConstraints()},
	} {
		for _, n := range group.names {
			for _, part := range strings.Split(n, ".") {
				if len(part) > 63 {
					t.Errorf("%s %q: %q is %d bytes; Postgres truncates identifiers at 63, so it never matches",
						group.kind, n, part, len(part))
				}
			}
		}
	}

	var dbname string
	if err := g.Raw(`SELECT current_database()`).Scan(&dbname).Error; err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil || u.Scheme == "" {
		t.Skip("TEST_DATABASE_URL is not a URL; cannot derive a second scratch database from it")
	}
	boot := dbname + "_bootstrap"
	if err := g.Exec(`DROP DATABASE IF EXISTS ` + boot).Error; err != nil {
		t.Fatalf("drop %s: %v", boot, err)
	}
	if err := g.Exec(`CREATE DATABASE ` + boot).Error; err != nil {
		t.Skipf("cannot create a scratch database for the bootstrap check: %v", err)
	}
	defer g.Exec(`DROP DATABASE IF EXISTS ` + boot)

	u.Path = "/" + boot
	raw, err := os.ReadFile(filepath.Join(migrationsDir(), "001_bootstrap.sql"))
	if err != nil {
		t.Fatal(err)
	}
	bdb, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer bdb.Close()
	if _, err := bdb.Exec(string(raw)); err != nil {
		t.Fatalf("001_bootstrap.sql on an empty database: %v", err)
	}
	bg, err := gorm.Open(postgres.New(postgres.Config{Conn: bdb}), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := services.VerifyPolicySchema(bg); err != nil {
		t.Fatalf("VerifyPolicySchema on a database built from 001_bootstrap.sql alone: %v", err)
	}
}
