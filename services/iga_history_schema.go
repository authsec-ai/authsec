package services

import (
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

// History and metrics (SPEC-secops-backend-upgrade.md W9) read tables that
// other workstreams add: agent_case (W3), the alert lifecycle columns (F6,
// F8), agent_containment.proof_state (W2), agent_capability_state (W1), agent
// (W7), detection rule versions (F6). A metric whose source is not in this
// database answers "unavailable" with the reason, and lights up once the
// table or column exists -- without a restart once the cache below expires.

// SchemaProbe reports whether a table, and optionally columns of it, exist.
type SchemaProbe interface {
	Has(table string, cols ...string) bool
}

// historySchemaTTL bounds how long a probe answer is reused.
const historySchemaTTL = time.Minute

type historySchemaEntry struct {
	cols map[string]bool // nil: the table does not exist
	at   time.Time
}

var historySchemaCache sync.Map // table -> historySchemaEntry

// ResetHistorySchemaCache forgets every cached probe answer (tests that
// create or drop a source table).
func ResetHistorySchemaCache() {
	historySchemaCache.Range(func(k, _ any) bool {
		historySchemaCache.Delete(k)
		return true
	})
}

// txSchemaProbe answers from pg_catalog on tx (readable whatever the role),
// cached per table.
type txSchemaProbe struct {
	tx  *gorm.DB
	err error
}

func newSchemaProbe(tx *gorm.DB) *txSchemaProbe { return &txSchemaProbe{tx: tx} }

func (p *txSchemaProbe) columns(table string) map[string]bool {
	if v, ok := historySchemaCache.Load(table); ok {
		e := v.(historySchemaEntry)
		if time.Since(e.at) < historySchemaTTL {
			return e.cols
		}
	}
	var names []string
	if err := p.tx.Raw(`SELECT attname::text FROM pg_attribute
	                     WHERE attrelid = to_regclass(?) AND attnum > 0 AND NOT attisdropped`, "public."+table).
		Scan(&names).Error; err != nil {
		p.err = err
		return nil
	}
	var cols map[string]bool
	if len(names) > 0 {
		cols = make(map[string]bool, len(names))
		for _, n := range names {
			cols[strings.ToLower(n)] = true
		}
	}
	historySchemaCache.Store(table, historySchemaEntry{cols: cols, at: time.Now()})
	return cols
}

// Has reports whether table exists with every column named.
func (p *txSchemaProbe) Has(table string, cols ...string) bool {
	c := p.columns(table)
	if c == nil {
		return false
	}
	for _, col := range cols {
		if !c[strings.ToLower(col)] {
			return false
		}
	}
	return true
}

// staticSchemaProbe is a fixed answer (unit tests): "table" or "table.column".
type staticSchemaProbe map[string]bool

func (s staticSchemaProbe) Has(table string, cols ...string) bool {
	if !s[table] {
		return false
	}
	for _, c := range cols {
		if !s[table+"."+c] {
			return false
		}
	}
	return true
}
