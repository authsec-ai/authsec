package igagraph_test

func init() {
	bfkCases = append(bfkCases,
		bfkCase{fk: "runtime_policy_targets_workload_fkey", kind: bfkWorkspace, build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.runtimePolicyTarget("workload_id", p.id("wl"))
		}},
		bfkCase{fk: "runtime_policy_targets_runtime_fkey", kind: bfkWorkspace, build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.runtimePolicyTarget("runtime_instance_id", p.id("runtime"))
		}},
	)
}
