package igagraph_test

import "github.com/google/uuid"

// discoveredAgentWorkload is a candidate join (042). The default names A's
// discovered agent and A's workload. A case overrides the one reference it tests.
func (s *bfkSide) discoveredAgentWorkload(set ...any) bfkRow {
	return bfkRowOf("discovered_agent_workloads", []any{
		"id", uuid.New(), "workspace_id", s.ws,
		"discovered_agent_id", s.id("dagent"), "workload_id", s.id("wl"),
		"link_strength", "candidate", "link_state", "proposed",
	}, set)
}
