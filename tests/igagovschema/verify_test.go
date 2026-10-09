package igagovschema_test

// T3.02, schema verification only: VerifyPolicySchema accepts the 056 schema
// and refuses one that lacks ANY single Phase 3 relation, naming it. (The 046
// refusal is in TestPhase3UpgradeOverExistingRows.) The IGA_POLICY gate,
// routes and capabilities are later T3.02 work and are not exercised here.

import (
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"

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
