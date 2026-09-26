package igagraph_test

import (
	"database/sql"
	"testing"
)

// A9 composite foreign keys. They live on ad_* tables and point at
// sync_configurations or ad_inventory_scopes, so the iga_*/cloud_* name
// scope does not see them. bfkExtraNames pulls in only these names. 039's
// single-column keys stay out of scope: the validate script drops them, and
// a case that named them would keep that drop from being safe.

func init() {
	bfkExtraNames = append(bfkExtraNames,
		"ad_inventory_scopes_config_ws_fkey",
		"ad_inventory_runs_config_ws_fkey",
		"ad_directory_instances_config_ws_fkey",
		"ad_inventory_cursors_scope_ws_fkey",
		"ad_directory_posture_run_fkey",
	)
	bfkCases = append(bfkCases,
		bfkCase{fk: "ad_inventory_scopes_config_ws_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.adInventoryScope("sync_config_id", p.id("adcfg"))
		}},
		bfkCase{fk: "ad_inventory_runs_config_ws_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.adInventoryRun("sync_config_id", p.id("adcfg"))
		}},
		bfkCase{fk: "ad_directory_instances_config_ws_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.adDirectoryInstance("sync_config_id", p.id("adcfg"))
		}},
		bfkCase{fk: "ad_inventory_cursors_scope_ws_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.adInventoryCursor("scope_id", p.id("adscope"))
		}},
		bfkCase{fk: "ad_directory_posture_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.adDirectoryPosture("run_id", p.id("adrun"))
		}},
	)
	bfkAfterSideSeed = append(bfkAfterSideSeed, func(t *testing.T, db *sql.DB, s *bfkSide) {
		s.put(t, db, "adscope", s.adInventoryScope())
		s.put(t, db, "adrun", s.adInventoryRun())
	})
}
