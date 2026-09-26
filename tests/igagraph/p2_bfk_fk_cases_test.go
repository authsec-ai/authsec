package igagraph_test

// One entry per foreign key in scope (bfkForeignKeys): every key on an iga_*
// or cloud_* table, Phase 1's included, and every key from any other table
// that points into one. TestB9ForeignKeyCatalogGuard fails if the catalog holds
// such a key with no entry here, if an entry names none, or if an entry's kind
// does not match the key's shape. So this list cannot drift from the schema
// without a test going red.
//
// build(w, p) returns the child row in workspace A. The reference under test
// names p's row and every other reference names A's rows. p is A for the
// control, B for foreign_workspace, A2 for foreign_integration and absent for
// the negatives that name no row at all (see bfkKind).

// bfkKind is what a foreign key protects. It decides which subtests a key gets.
type bfkKind int

const (
	// bfkWorkspace: a composite (workspace_id, ...) reference. It must reject a
	// parent that exists only in workspace B.
	bfkWorkspace bfkKind = iota
	// bfkIntegration: an integration-qualified (workspace_id, connector_id, ...)
	// reference to a collection fact (035). It must also reject a parent in the
	// SAME workspace under ANOTHER integration (B20).
	bfkIntegration
	// bfkAnchor: the single-column reference to workspaces(id). workspaces is
	// the tenant root, not a workspace-scoped table, so no parent can belong to
	// another workspace. The negative names a workspace that does not exist.
	bfkAnchor
	// bfkLegacy: a single-column reference to a workspace-scoped table,
	// written before §2.9's rule and not converted by 027-036. Listed in
	// bfkLegacySingleColumn with its origin. Its subtests show what it enforces
	// (existence) and pin the gap it leaves (another workspace's parent is
	// ADMITTED), so the exemption cannot outlive the gap unnoticed.
	bfkLegacy
)

func (k bfkKind) String() string {
	return [...]string{"workspace", "integration", "anchor", "legacy"}[k]
}

type bfkCase struct {
	fk   string
	kind bfkKind
	// deferred: the constraint is DEFERRABLE INITIALLY DEFERRED, so its
	// negative is asserted at COMMIT. Checked against the catalog.
	deferred bool
	build    func(w *bfkWorld, p *bfkSide) bfkRow
}

// bfkAnchorCase is the workspaces anchor of table: the child row names p's
// workspace.
func bfkAnchorCase(fk string, row func(a *bfkSide, set ...any) bfkRow) bfkCase {
	return bfkCase{fk: fk, kind: bfkAnchor, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return row(w.A, "workspace_id", p.ws)
	}}
}

var bfkCases = []bfkCase{
	// ---------------- 027: provenance converted to (workspace_id, id) --------
	{fk: "cloud_scan_run_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.scanRun("connector_id", p.conn)
	}},
	{fk: "cloud_observation_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observation("connector_id", p.conn)
	}},
	{fk: "cloud_observation_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observation("scan_run_id", p.id("run"))
	}},
	{fk: "cloud_observation_last_confirmed_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observation("last_confirmed_run_id", p.id("run"))
	}},
	bfkAnchorCase("iga_pipeline_lease_workspace_fkey", (*bfkSide).pipelineLease),

	// ---------------- pre-027 single-column references (bfkLegacy) ----------
	{fk: "cloud_identity_connector_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudIdentity("connector_id", p.conn)
	}},
	{fk: "cloud_observation_identity_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observation("identity_id", p.id("cuser"))
	}},
	{fk: "cloud_observation_permission_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observation("permission_id", p.id("cperm"))
	}},
	{fk: "cloud_observation_resource_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observation("resource_id", p.id("cres"))
	}},
	{fk: "cloud_observation_workload_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observation("workload_id", p.id("cwl"))
	}},
	{fk: "iga_observations_delivery_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.igaObservation("delivery_id", p.id("delivery"))
	}},

	// ---------------- Phase 1's cloud_* tables (011-017), bfkLegacy ----------
	// Written before §2.9 and converted by none of 027-036. Five of them are
	// single-column references to cloud_identity: B20's "Catches" class, on
	// the tables Phase 1 still writes.
	{fk: "cloud_secret_connector_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudSecret("connector_id", p.conn)
	}},
	{fk: "cloud_secret_identity_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudSecret("identity_id", p.id("cuser"))
	}},
	{fk: "cloud_assume_edge_connector_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudAssumeEdge("connector_id", p.conn)
	}},
	{fk: "cloud_assume_edge_identity_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudAssumeEdge("identity_id", p.id("cuser"))
	}},
	{fk: "cloud_permission_connector_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudPermission("connector_id", p.conn)
	}},
	{fk: "cloud_permission_identity_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudPermission("identity_id", p.id("cuser"))
	}},
	// cloud_permission_scope_resource_chk: a resource exactly when scoped to one.
	{fk: "cloud_permission_resource_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudPermission("scope_kind", "resource", "resource_id", p.id("cres"))
	}},
	{fk: "cloud_resource_connector_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudResource("connector_id", p.conn)
	}},
	{fk: "cloud_workload_connector_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudWorkload("connector_id", p.conn)
	}},
	{fk: "cloud_workload_identity_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudWorkload("identity_id", p.id("cuser"))
	}},
	{fk: "cloud_usage_connector_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudUsage("connector_id", p.conn)
	}},
	{fk: "cloud_usage_identity_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudUsage("identity_id", p.id("cuser"))
	}},
	{fk: "cloud_scan_checkpoint_connector_id_fkey", kind: bfkLegacy, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudScanCheckpoint("connector_id", p.conn)
	}},

	// ---------------- references INTO the graph from outside it -------------
	// discovered_agent_iga_links is Discovery's table (001), not the graph's,
	// but its key names an iga_agents row, so it is held to §2.9 too. Its
	// other keys point at Discovery's own tables and are out of scope.
	{fk: "discovered_agent_iga_links_iga_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.discoveredLink("iga_agent_id", p.id("agent"))
	}},

	// ---------------- 004: the estate and the GitHub path --------------------
	bfkAnchorCase("iga_integrations_workspace_fkey", (*bfkSide).integration),
	{fk: "iga_integration_scopes_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.integrationScope("integration_id", p.id("integ"))
	}},
	{fk: "iga_integration_scopes_estate_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.integrationScope("estate_scope_id", p.id("scope"))
	}},
	{fk: "iga_scan_runs_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.igaScanRun("integration_id", p.id("integ"))
	}},
	{fk: "iga_scan_checkpoints_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.scanCheckpoint("scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_coverage_states_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.coverageState("integration_id", p.id("integ"))
	}},
	{fk: "iga_coverage_states_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.coverageState("integration_scope_id", p.id("iscope"))
	}},
	bfkAnchorCase("iga_webhook_deliveries_workspace_fkey", (*bfkSide).delivery),
	{fk: "iga_durable_jobs_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.durableJob("integration_id", p.id("integ"))
	}},
	{fk: "iga_source_objects_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.sourceObject("integration_id", p.id("integ"))
	}},
	{fk: "iga_observations_scan_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.igaObservation("scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_observations_source_object_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.igaObservation("source_object_id", p.id("srcobj"))
	}},
	{fk: "iga_classification_candidates_source_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.candidate("source_object_id", p.id("srcobj"))
	}},
	{fk: "iga_correlations_source_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.correlation("source_object_id", p.id("srcobj"))
	}},
	bfkAnchorCase("iga_estate_scopes_workspace_fkey", (*bfkSide).estateScope),
	{fk: "iga_estate_scopes_parent_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.estateScope("parent_scope_id", p.id("scope"))
	}},
	bfkAnchorCase("iga_agents_workspace_fkey", (*bfkSide).agent),
	{fk: "iga_agents_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.agent("estate_scope_id", p.id("scope"))
	}},
	{fk: "iga_agent_instances_agent_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.agentInstance("agent_id", p.id("agent"))
	}},
	{fk: "iga_agent_instances_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.agentInstance("estate_scope_id", p.id("scope"))
	}},
	bfkAnchorCase("iga_identity_accounts_workspace_fkey", (*bfkSide).identity),
	{fk: "iga_identity_accounts_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.identity("estate_scope_id", p.id("scope"))
	}},
	{fk: "iga_credentials_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.credential("identity_account_id", p.id("ident"))
	}},
	bfkAnchorCase("iga_resources_workspace_fkey", (*bfkSide).resource),
	{fk: "iga_resources_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.resource("estate_scope_id", p.id("scope"))
	}},
	bfkAnchorCase("iga_entitlements_workspace_fkey", (*bfkSide).statement),
	// The grant's own 004 references (gap notes: "the 004 FKs the grant
	// depends on"). A resource-typed entitlement is the GitHub shape.
	{fk: "iga_entitlements_resource_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.statement("provider", "github", "policy_id", nil, "native_grant_kind", "repo_permission",
			"resource_id", p.id("res"))
	}},
	bfkAnchorCase("iga_access_edges_workspace_fkey", (*bfkSide).grant),
	{fk: "iga_access_edges_entitlement_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.grant("entitlement_id", p.id("ent"))
	}},
	// iga_access_edges_aws_grant_chk forbids a resource on an AWS grant, so
	// the resource-typed edge is the GitHub shape (no typed subject).
	{fk: "iga_access_edges_resource_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.grant("provider", "github", "subject_kind", "agent", "subject_id", w.A.id("agent"),
			"subject_identity_account_id", nil, "entitlement_id", nil, "assignment_id", nil,
			"resource_id", p.id("res"))
	}},
	bfkAnchorCase("iga_canonical_attribute_values_workspace_fkey", (*bfkSide).canonicalValue),
	{fk: "iga_canonical_attribute_values_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.canonicalValue("observation_id", p.id("iobs"))
	}},
	bfkAnchorCase("iga_attribute_authority_policies_workspace_fkey", (*bfkSide).authorityPolicy),
	{fk: "iga_observation_links_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observationLink("observation_id", p.id("iobs"))
	}},
	bfkAnchorCase("iga_ownership_candidates_workspace_fkey", (*bfkSide).ownershipCandidate),
	{fk: "iga_operational_issues_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.operationalIssue("integration_id", p.id("integ"))
	}},
	bfkAnchorCase("iga_idempotency_keys_workspace_fkey", (*bfkSide).idempotencyKey),

	// ---------------- 029: workloads and classification ----------------------
	bfkAnchorCase("iga_workload_workspace_fkey", (*bfkSide).workload),
	{fk: "iga_workload_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.workload("estate_scope_id", p.id("scope"))
	}},
	{fk: "iga_wc_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.classification("workload_id", p.id("wl"))
	}},
	{fk: "iga_wc_undoes_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.classification("undoes_decision_id", p.id("wc"))
	}},
	bfkAnchorCase("iga_classification_clock_workspace_fkey", (*bfkSide).classificationClock),

	// ---------------- 030: the grant's typed subject and provenance ----------
	{fk: "iga_access_edges_subject_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		// subject_id moves with it: iga_access_edges_subject_agree_chk.
		return w.A.grant("subject_id", p.id("ident"), "subject_identity_account_id", p.id("ident"))
	}},
	{fk: "iga_access_edges_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.grant("connector_id", p.conn)
	}},
	{fk: "iga_access_edges_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.grant("last_confirmed_by", p.id("run"))
	}},

	// ---------------- 031 and 034: relationships -----------------------------
	bfkAnchorCase("iga_relationship_workspace_fkey", (*bfkSide).relationship),
	{fk: "iga_relationship_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationship("connector_id", p.conn)
	}},
	{fk: "iga_rel_src_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationship("relationship_type", "member_of", "source_workload_id", nil,
			"source_identity_account_id", p.id("ident"))
	}},
	{fk: "iga_rel_src_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationship("source_workload_id", p.id("wl"))
	}},
	{fk: "iga_rel_tgt_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationship("target_identity_account_id", p.id("ident"))
	}},
	{fk: "iga_relationship_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationship("last_confirmed_by", p.id("run"))
	}},
	{fk: "iga_rel_src_external_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationship("relationship_type", "can_assume", "mechanism", "oidc_federation",
			"source_workload_id", nil, "source_external_principal_id", p.id("ep"))
	}},
	bfkAnchorCase("iga_external_principal_workspace_fkey", (*bfkSide).externalPrincipal),
	{fk: "iga_ep_resolved_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.externalPrincipal("resolved_identity_account_id", p.id("ident"),
			"resolution_basis", "derived", "resolution_rule", "bfk")
	}},
	{fk: "iga_ep_resolved_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.externalPrincipal("resolved_workload_id", p.id("wl"),
			"resolution_basis", "derived", "resolution_rule", "bfk")
	}},

	// ---------------- 032: evidence junctions and per-source support ---------
	{fk: "iga_access_edge_evidence_edge_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.edgeEvidence("access_edge_id", p.id("edge"))
	}},
	{fk: "iga_access_edge_evidence_obs_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.edgeEvidence("observation_id", p.id("obs"))
	}},
	{fk: "iga_relationship_evidence_rel_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationshipEvidence("relationship_id", p.id("rel"))
	}},
	{fk: "iga_relationship_evidence_obs_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationshipEvidence("observation_id", p.id("obs"))
	}},
	bfkAnchorCase("iga_object_support_workspace_fkey", (*bfkSide).support),
	{fk: "iga_object_support_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("connector_id", p.conn)
	}},
	{fk: "iga_os_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("identity_account_id", p.id("ident"))
	}},
	{fk: "iga_os_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("identity_account_id", nil, "workload_id", p.id("wl"))
	}},
	{fk: "iga_os_resource_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("identity_account_id", nil, "resource_id", p.id("res"))
	}},
	{fk: "iga_os_entitlement_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("identity_account_id", nil, "entitlement_id", p.id("ent"))
	}},
	{fk: "iga_os_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("last_confirmed_run_id", p.id("run"))
	}},

	// ---------------- 033: projection job, watermark, publication ------------
	bfkAnchorCase("iga_projection_job_workspace_fkey", (*bfkSide).projectionJob),
	{fk: "iga_projection_job_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.projectionJob("scan_run_id", p.id("run"))
	}},
	{fk: "iga_projection_job_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.projectionJob("connector_id", p.conn)
	}},
	bfkAnchorCase("iga_projection_state_workspace_fkey", (*bfkSide).projectionState),
	{fk: "iga_projection_state_scope_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.projectionState("estate_scope_id", p.id("scope"))
	}},
	{fk: "iga_projection_state_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.projectionState("last_run_id", p.id("run"))
	}},
	{fk: "iga_projection_state_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.projectionState("connector_id", p.conn)
	}},
	bfkAnchorCase("iga_publication_workspace_fkey", (*bfkSide).publication),
	{fk: "iga_publication_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.publication("scan_run_id", p.id("run2"))
	}},

	// ---------------- 035: the collection model (B20) ------------------------
	// The connector references are workspace-qualified only: they point at
	// cloud_connector itself.
	{fk: "cloud_gm_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.membership("connector_id", p.conn)
	}},
	{fk: "cloud_gm_user_fkey", kind: bfkIntegration, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.membership("user_identity_id", p.id("cuser"))
	}},
	{fk: "cloud_gm_group_fkey", kind: bfkIntegration, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.membership("group_identity_id", p.id("cgroup"))
	}},
	{fk: "cloud_policy_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudPolicy("connector_id", p.conn)
	}},
	{fk: "cloud_policy_holder_fkey", kind: bfkIntegration, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.cloudPolicy("policy_kind", "inline", "holder_identity_id", p.id("cuser"))
	}},
	{fk: "cloud_pa_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.attachment("connector_id", p.conn)
	}},
	{fk: "cloud_pa_policy_fkey", kind: bfkIntegration, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.attachment("policy_row_id", p.id("cpol"))
	}},
	{fk: "cloud_pa_principal_fkey", kind: bfkIntegration, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.attachment("principal_identity_id", p.id("cuser"))
	}},
	{fk: "cloud_observation_policy_fkey", kind: bfkIntegration, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.observation("policy_id", p.id("cpol"))
	}},

	// ---------------- 036: the permission model ------------------------------
	bfkAnchorCase("iga_policy_workspace_fkey", (*bfkSide).policy),
	{fk: "iga_entitlements_policy_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.statement("policy_id", p.id("pol"))
	}},
	{fk: "iga_sr_entitlement_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.statementRevision("entitlement_id", p.id("ent"))
	}},
	{fk: "iga_sr_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.statementRevision("first_seen_run_id", p.id("run"))
	}},
	{fk: "iga_et_entitlement_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.target("entitlement_id", p.id("ent"))
	}},
	{fk: "iga_et_resource_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.target("resource_id", p.id("res"))
	}},
	{fk: "iga_pa_policy_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignment("policy_id", p.id("pol"))
	}},
	{fk: "iga_pa_holder_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignment("holder_identity_account_id", p.id("ident"))
	}},
	{fk: "iga_pa_connector_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignment("connector_id", p.conn)
	}},
	{fk: "iga_pa_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignment("last_confirmed_by", p.id("run"))
	}},
	{fk: "iga_ae_assignment_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignmentEvidence("assignment_id", p.id("assign"))
	}},
	{fk: "iga_ae_obs_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignmentEvidence("observation_id", p.id("obs"))
	}},
	{fk: "iga_access_edges_assignment_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.grant("assignment_id", p.id("assign"))
	}},
	{fk: "iga_os_policy_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("identity_account_id", nil, "policy_id", p.id("pol"))
	}},
	// The event names p's revision. B's rev 7 exists only in B; the absent
	// side's 999 exists nowhere. DEFERRED: 036 writes the publication at the
	// end of the same transaction as its events.
	{fk: "iga_le_publication_fkey", deferred: true, build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.lifecycleEvent("rev", p.rev)
	}},
	{fk: "iga_le_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.lifecycleEvent("scan_run_id", p.id("run"))
	}},
	{fk: "iga_le_identity_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.lifecycleEvent("identity_account_id", p.id("ident"))
	}},
	{fk: "iga_le_workload_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.lifecycleEvent("identity_account_id", nil, "workload_id", p.id("wl"))
	}},
	{fk: "iga_le_resource_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.lifecycleEvent("identity_account_id", nil, "resource_id", p.id("res"))
	}},
	{fk: "iga_le_entitlement_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.lifecycleEvent("identity_account_id", nil, "entitlement_id", p.id("ent"))
	}},
	{fk: "iga_le_policy_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.lifecycleEvent("identity_account_id", nil, "policy_id", p.id("pol"))
	}},

	// ---------------- 038: collector registry --------------------------------
	// These keys are in scope because the parent is iga_* (or, for the
	// observation, the child is). A same-workspace parent is the control; a
	// parent that exists only in another workspace is refused.
	{fk: "collector_enrollments_estate_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.collectorEnrollment("estate_scope_id", p.id("scope"))
	}},
	{fk: "collector_instances_estate_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.collectorInstance("estate_scope_id", p.id("scope"))
	}},
	{fk: "collector_instances_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.collectorInstance("integration_id", p.id("integ"))
	}},
	{fk: "collector_integrations_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.collectorIntegration("integration_id", p.id("integ"))
	}},
	{fk: "collector_batches_scan_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.collectorBatch("iga_scan_run_id", p.id("iscan"))
	}},
	{fk: "collector_outbox_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.collectorOutbox("integration_id", p.id("integ"))
	}},
	{fk: "iga_observations_discovery_source_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.igaObservation("discovery_source_id", p.id("dsrc"))
	}},

	// ---------------- 039: AD inventory runs point into the evidence tables --
	// In scope because the parent is iga_integrations or iga_scan_runs. The
	// child lives in A; the column under test names p, so a parent that exists
	// only in another workspace is refused.
	{fk: "ad_inventory_runs_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.adInventoryRun("integration_id", p.id("integ"))
	}},
	{fk: "ad_inventory_runs_scan_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.adInventoryRun("scan_run_id", p.id("iscan"))
	}},

	// ---------------- 040: typed collector provenance ------------------------
	{fk: "iga_object_support_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("connector_id", nil, "integration_id", p.id("integ"),
			"confirming_iga_scan_run_id", w.A.id("iscan"))
	}},
	{fk: "iga_object_support_confirming_iga_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.support("connector_id", nil, "integration_id", w.A.id("integ"),
			"confirming_iga_scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_relationship_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationship("integration_id", p.id("integ"))
	}},
	{fk: "iga_relationship_confirming_iga_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationship("integration_id", w.A.id("integ"), "confirming_iga_scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_access_edges_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.grant("integration_id", p.id("integ"))
	}},
	{fk: "iga_access_edges_confirming_iga_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.grant("integration_id", w.A.id("integ"), "confirming_iga_scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_policy_assignment_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignment("integration_id", p.id("integ"))
	}},
	{fk: "iga_policy_assignment_confirming_iga_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignment("integration_id", w.A.id("integ"), "confirming_iga_scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_access_edge_evidence_iga_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.edgeEvidence("observation_id", nil, "iga_observation_id", p.id("iobs"))
	}},
	{fk: "iga_relationship_evidence_iga_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.relationshipEvidence("observation_id", nil, "iga_observation_id", p.id("iobs"))
	}},
	{fk: "iga_assignment_evidence_iga_observation_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.assignmentEvidence("observation_id", nil, "iga_observation_id", p.id("iobs"))
	}},
	{fk: "iga_projection_job_iga_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.projectionJob("scan_run_id", nil, "connector_id", nil, "iga_scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_projection_state_integration_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.projectionState("connector_id", nil, "last_run_id", nil,
			"integration_id", p.id("integ"), "last_iga_scan_run_id", w.A.id("iscan"))
	}},
	{fk: "iga_projection_state_iga_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.projectionState("connector_id", nil, "last_run_id", nil,
			"integration_id", w.A.id("integ"), "last_iga_scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_publication_iga_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.publication("scan_run_id", nil, "iga_scan_run_id", p.id("iscan"))
	}},
	{fk: "iga_pipeline_lease_iga_run_fkey", build: func(w *bfkWorld, p *bfkSide) bfkRow {
		return w.A.pipelineLease("state", "projecting", "holder", "job:bfk", "iga_scan_run_id", p.id("iscan"))
	}},
}
