package igagraph_test

import (
	"github.com/google/uuid"
)

// adInventoryScope is a parent for the cursor key and a child for the
// configuration key. object_classes is omitted so the column default applies:
// a parameterized text value does not cast to jsonb.
func (s *bfkSide) adInventoryScope(set ...any) bfkRow {
	return bfkRowOf("ad_inventory_scopes", []any{
		"id", uuid.New(), "workspace_id", s.ws, "sync_config_id", s.id("adcfg"),
		"base_dn", bfkFresh("dn"),
	}, set)
}

// adInventoryCursor has no id column. Do not seed it with put.
func (s *bfkSide) adInventoryCursor(set ...any) bfkRow {
	return bfkRowOf("ad_inventory_cursors", []any{
		"workspace_id", s.ws, "scope_id", s.id("adscope"), "tracking_mode", "usn",
	}, set)
}

// adDirectoryInstance is not seeded. The unique (workspace_id, sync_config_id)
// would collide with the control row, which uses this side's configuration.
func (s *bfkSide) adDirectoryInstance(set ...any) bfkRow {
	return bfkRowOf("ad_directory_instances", []any{
		"id", uuid.New(), "workspace_id", s.ws, "sync_config_id", s.id("adcfg"),
		"forest_id", bfkFresh("forest"),
	}, set)
}

// adDirectoryPosture points at the seeded run. JSON columns keep their defaults.
func (s *bfkSide) adDirectoryPosture(set ...any) bfkRow {
	return bfkRowOf("ad_directory_posture", []any{
		"id", uuid.New(), "workspace_id", s.ws, "run_id", s.id("adrun"),
		"object_guid", bfkFresh("guid"), "account_kind", "ad_user", "coverage", "complete",
	}, set)
}
