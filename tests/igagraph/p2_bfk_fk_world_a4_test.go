package igagraph_test

import (
	"time"

	"github.com/google/uuid"
)

func init() {
	bfkExtraParents = append(bfkExtraParents, func(s *bfkSide) (string, bfkRow) {
		return "runtime", s.runtimeInstance()
	})
}

func (s *bfkSide) runtimeInstance(set ...any) bfkRow {
	return bfkRowOf("iga_runtime_instances", []any{"id", uuid.New(), "workspace_id", s.ws,
		"workload_id", s.id("wl"), "runtime_key", bfkFresh("rt"), "runtime_kind", "process",
		"last_observed_at", time.Now()}, set)
}

func (s *bfkSide) runtimeBinding(set ...any) bfkRow {
	return bfkRowOf("iga_runtime_identity_bindings", []any{"id", uuid.New(), "workspace_id", s.ws,
		"runtime_instance_id", s.id("runtime"), "identity_account_id", s.id("ident"),
		"binding_kind", "uid", "basis", "observed", "observation_id", s.id("iobs"),
		"valid_from", time.Now()}, set)
}

func (s *bfkSide) observedAccess(set ...any) bfkRow {
	return bfkRowOf("iga_observed_access", []any{"id", uuid.New(), "workspace_id", s.ws,
		"workload_id", s.id("wl"), "runtime_instance_id", s.id("runtime"),
		"resource_id", s.id("res"), "observation_id", s.id("iobs"),
		"action", bfkFresh("act"), "outcome", "success", "observed_at", time.Now()}, set)
}

func (s *bfkSide) workloadResourceBinding(set ...any) bfkRow {
	return bfkRowOf("iga_workload_resource_bindings", []any{"id", uuid.New(), "workspace_id", s.ws,
		"workload_id", s.id("wl"), "resource_id", s.id("res"), "binding_kind", "mount",
		"observation_id", s.id("iobs"), "source_key", bfkFresh("wrb")}, set)
}

func (s *bfkSide) workloadPolicyBinding(set ...any) bfkRow {
	return bfkRowOf("iga_workload_policy_bindings", []any{"id", uuid.New(), "workspace_id", s.ws,
		"workload_id", s.id("wl"), "policy_id", s.id("pol"), "binding_kind", "systemd",
		"observation_id", s.id("iobs"), "source_key", bfkFresh("wpb")}, set)
}
