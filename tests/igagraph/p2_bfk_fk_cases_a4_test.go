package igagraph_test

func init() {
	bfkCases = append(bfkCases,
		bfkAnchorCase("iga_runtime_instances_workspace_fkey", (*bfkSide).runtimeInstance),
		bfkCase{fk: "iga_runtime_instances_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.runtimeInstance("workload_id", p.id("wl"))
		}},
		bfkCase{fk: "iga_runtime_instances_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.runtimeInstance("estate_scope_id", p.id("scope"))
		}},
		bfkCase{fk: "iga_runtime_instances_parent_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.runtimeInstance("parent_runtime_id", p.id("runtime"))
		}},

		bfkAnchorCase("iga_runtime_identity_bindings_workspace_fkey", (*bfkSide).runtimeBinding),
		bfkCase{fk: "iga_rib_runtime_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.runtimeBinding("runtime_instance_id", p.id("runtime"))
		}},
		bfkCase{fk: "iga_rib_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.runtimeBinding("identity_account_id", p.id("ident"))
		}},
		bfkCase{fk: "iga_rib_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.runtimeBinding("observation_id", p.id("iobs"))
		}},

		bfkAnchorCase("iga_observed_access_workspace_fkey", (*bfkSide).observedAccess),
		bfkCase{fk: "iga_observed_access_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.observedAccess("workload_id", p.id("wl"))
		}},
		bfkCase{fk: "iga_observed_access_runtime_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.observedAccess("runtime_instance_id", p.id("runtime"))
		}},
		bfkCase{fk: "iga_observed_access_runtime_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.observedAccess("workload_id", w.A.id("wl"), "runtime_instance_id", p.id("runtime"))
		}},
		bfkCase{fk: "iga_observed_access_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.observedAccess("identity_account_id", p.id("ident"))
		}},
		bfkCase{fk: "iga_observed_access_resource_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.observedAccess("resource_id", p.id("res"))
		}},
		bfkCase{fk: "iga_observed_access_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.observedAccess("observation_id", p.id("iobs"))
		}},

		bfkAnchorCase("iga_wrb_workspace_fkey", (*bfkSide).workloadResourceBinding),
		bfkCase{fk: "iga_wrb_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.workloadResourceBinding("workload_id", p.id("wl"))
		}},
		bfkCase{fk: "iga_wrb_resource_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.workloadResourceBinding("resource_id", p.id("res"))
		}},
		bfkCase{fk: "iga_wrb_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.workloadResourceBinding("observation_id", p.id("iobs"))
		}},

		bfkAnchorCase("iga_wpb_workspace_fkey", (*bfkSide).workloadPolicyBinding),
		bfkCase{fk: "iga_wpb_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.workloadPolicyBinding("workload_id", p.id("wl"))
		}},
		bfkCase{fk: "iga_wpb_policy_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.workloadPolicyBinding("policy_id", p.id("pol"))
		}},
		bfkCase{fk: "iga_wpb_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.workloadPolicyBinding("observation_id", p.id("iobs"))
		}},

		bfkCase{fk: "iga_pa_estate_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
			return w.A.assignment("assignment_estate_scope_id", p.id("scope"))
		}},
	)
}
