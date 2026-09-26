package igagraph_test

import "github.com/google/uuid"

func init() {
	bfkExtraParents = append(bfkExtraParents,
		func(s *bfkSide) (string, bfkRow) { return "rtpol", s.runtimePolicy() },
		func(s *bfkSide) (string, bfkRow) { return "rtpub", s.runtimePublication() },
	)
}

func (s *bfkSide) runtimePolicy(set ...any) bfkRow {
	return bfkRowOf("runtime_policies", []any{"id", uuid.New(), "workspace_id", s.ws,
		"name", bfkFresh("rt"), "owner_user_id", uuid.New(),
		"current_draft_revision", 1, "lifecycle", "draft"}, set)
}

func (s *bfkSide) runtimePublication(set ...any) bfkRow {
	return bfkRowOf("runtime_policy_publications", []any{"id", uuid.New(), "workspace_id", s.ws,
		"policy_id", s.id("rtpol"), "revision", 1,
		"revision_hash", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"author_user_id", uuid.New()}, set)
}

func (s *bfkSide) runtimePolicyTarget(set ...any) bfkRow {
	return bfkRowOf("runtime_policy_targets", []any{"id", uuid.New(), "workspace_id", s.ws,
		"publication_id", s.id("rtpub"), "workload_id", s.id("wl"),
		"collector_id", s.id("cinst"), "desired_delivery_revision", int64(1)}, set)
}
