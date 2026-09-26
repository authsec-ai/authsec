package igagraph_test

import "github.com/google/uuid"

// 042's composite keys. An authoritative instance names a workload only with
// human_registration, an actor, an owner and a classification version, and
// exactly one observation arm. The arm that is not under test names A's row
// so the authority CHECK passes while the foreign parent is the one refused.
func init() {
	authority := []any{
		"workload_link_basis", "human_registration",
		"linked_by", uuid.New(),
		"owner_user_id", uuid.New(),
		"classification_version", int64(1),
		"link_purpose", "bfk",
	}
	bfkCases = append(bfkCases,
		bfkCase{fk: "iga_agent_instances_workload_fkey", kind: bfkWorkspace, build: func(w *bfkWorld, p *bfkSide) bfkRow {
			set := append([]any{"workload_id", p.id("wl"), "observation_id", w.A.id("iobs")}, authority...)
			return w.A.agentInstance(set...)
		}},
		bfkCase{fk: "iga_agent_instances_observation_fkey", kind: bfkWorkspace, build: func(w *bfkWorld, p *bfkSide) bfkRow {
			set := append([]any{"workload_id", w.A.id("wl"), "observation_id", p.id("iobs")}, authority...)
			return w.A.agentInstance(set...)
		}},
		bfkCase{fk: "iga_agent_instances_cloud_observation_fkey", kind: bfkWorkspace, build: func(w *bfkWorld, p *bfkSide) bfkRow {
			set := append([]any{"workload_id", w.A.id("wl"), "cloud_observation_id", p.id("obs")}, authority...)
			return w.A.agentInstance(set...)
		}},
		bfkCase{fk: "discovered_agent_workloads_workload_fkey", kind: bfkWorkspace, build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.discoveredAgentWorkload("workload_id", p.id("wl"))
		}},
		bfkCase{fk: "discovered_agent_workloads_observation_fkey", kind: bfkWorkspace, build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.discoveredAgentWorkload("observation_id", p.id("iobs"))
		}},
		bfkCase{fk: "discovered_agent_workloads_cloud_observation_fkey", kind: bfkWorkspace, build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.discoveredAgentWorkload("cloud_observation_id", p.id("obs"))
		}},
	)
}
