package repositories

import (
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// Catalog checks for schema verification gates (the partners of HasRelation
// and HasColumn): which of the named triggers and constraints exist in the
// public schema. Two queries whatever the number of names, so a gate can
// check every invariant of its migrations cheaply. Lives here, outside the
// iga_* files, because it reads the PostgreSQL catalog
// (scripts/ci-iga-isolation-check.sh).

// EnabledTriggers returns which of names ("table.trigger") exist in public
// and are not DISABLED.
func EnabledTriggers(db *gorm.DB, names []string) ([]string, error) {
	var have []string
	err := db.Raw(`SELECT c.relname || '.' || t.tgname
		  FROM pg_trigger t
		  JOIN pg_class c ON c.oid = t.tgrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public' AND NOT t.tgisinternal AND t.tgenabled <> 'D'
		   AND c.relname || '.' || t.tgname = ANY(?)`, pq.Array(names)).Scan(&have).Error
	return have, err
}

// ValidatedConstraints returns which of names ("table.constraint") exist in
// public and are validated.
func ValidatedConstraints(db *gorm.DB, names []string) ([]string, error) {
	var have []string
	err := db.Raw(`SELECT c.relname || '.' || k.conname
		  FROM pg_constraint k
		  JOIN pg_class c ON c.oid = k.conrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public' AND k.convalidated
		   AND c.relname || '.' || k.conname = ANY(?)`, pq.Array(names)).Scan(&have).Error
	return have, err
}
