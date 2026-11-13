# Local demo status: instrumentation, policy discovery, UI, enforcement

Date: 2026-10-28. Branch: `experimental` on the Authsec checkouts (`authsec`, `Authsec-ui`, `iga-local`, `iga-agent`, `iga-host-collector`, `iga-gateway-drivers`).

This is the state of the local demo, not a claim that the same behaviour is running on `authsec-staging` or `main`.

## Accomplished

### Instrumentation

Runtime activity is a first-class input, not a side log.

- The host collector and the in-cluster agent record process and workload sightings, including framework signals in the image, path, command, and environment.
- Collector observations are projected into `iga_runtime_activity` (`ActivityProjector`). Each observation is one activity row, idempotent on workspace, collector, and event id.
- A discovered agent that has been seen doing something carries that activity on `metadata.activity`. A sighting with no activity is not turned into a policy.
- The live kind pod for the sample researcher is stored as a runtime instance and is drawn on the identity graph through a `runtime_binding` edge. The graph reader loads that instance; an earlier read failed once the workload was supported because the instance type was reached but not fetched.
- Sample identity-graph rows are in the demo workspace: the researcher workload runs as the `langchain-sample-agent` service account, and that account is a member of `system:serviceaccounts:agents`.

What this does not yet prove: the host collector process is not staying up, so new host observations are not arriving. See Pending.

### Discovery of policies

Discovery of agents and discovery of policies are separate steps.

- A sighting is stored as a candidate wherever it is seen. Promotion into `discovered_agents` is limited to medium and high confidence. None and low stay held. A generic API key alone does not become an agent. The same logical agent is one row only when a specific logical key matches; an empty key does not merge processes that merely share a binary name.
- When a discovered agent has activity and `IGA_V2_POLICY` is on, `RunRuntimePolicyDiscovery` calls `DiscoverFromAgent` and upserts a draft runtime policy from that activity. An administrator's edit of a draft is left in place. A held candidate, and an attach that has no activity, does not call `DiscoverFromAgent`.
- The policy lifecycle in the API and the UI is draft, validated, simulated, approved, then published. Approved means signed off. Published means collectors are asked to follow that revision. Saving rules on an already published policy inserts the next revision as a new draft. The last publication stays in effect until that new draft is approved and published.
- The researcher workload in the local demo is joined to its published observe policy by `iga_workload.source_key = discovered-agent:<id>` and `targets.workload_ids` on the current revision. The Controls tab reads the compiled controls artifact.

### Integration with the UI

The IGA console can show the objects the pipeline produces.

- Explore lists Cloud Agents, Local Agents, Identities, and Resources when graph projection is on. Local Agents reads `discovered_agents`. A process with no adopted workload does not request an empty graph root.
- The researcher identity graph draws: deployment runs as the service account, the account is a member of the group, and the live pod is attached. On a phone-width window the same neighbourhood opens in the Paths view.
- Cloud Agents stays an AWS list by default. When that AWS list is empty and another provider has a workload, the page shows that workload's identity graph instead of an empty estate. Identities does the same for the Kubernetes service account and group.
- Runtime Policies is in Governance. Publish is an explicit observe publication. The create and detail screens show the lifecycle, the compiled controls, and the agent binding.

### Enforcement

Enforcement is implemented as a refused mode, not as a live block.

- Publication accepts `observe` or `enforce`. `enforce` returns 403 `enforce_disabled` while `IGA_V2_ENFORCE` is unset. The local demo publishes only in observe mode. Observe records the decision and does not install a NetworkPolicy.
- The collector and the in-cluster agent contain the control installers (including Tetragon in observe mode, seccomp, landlock, and the launcher). The gateway verifies a signed policy bundle. None of that is actuating in this demo: the enforce flag is off, and the host collector is not healthy enough to apply a desired bundle.
- Quarantine remains a recorded state. It does not remove a workload.

## Pending

### Instrumentation

- The host collector restarts with `credential rejected`. It is still enrolled, so it has not been enrolled again. Until that credential is accepted, host process sightings and Tetragon observations are not streaming.
- The researcher's pod is on the graph, but there is no runtime-identity binding, so the pod does not walk onward to the service account. The account is reached only by the declared `executes_as` edge.
- Four Kubernetes resources seen in activity (Grok API, GitHub API, X API, and the sample file) have no support row and no graph edge. Observed access still requires a runtime instance and an observation, and an observation requires a source object plus a scan run or a delivery.

### Discovery of policies

- Policy discovery runs only for agents whose metadata already contains an activity array. Agents that are held, or that attach with no activity, stay without a generated policy. That is intentional; it is also why a newly discovered process does not grow a policy until activity is recorded.
- A known ordering limit remains: the host container named `langchain-sample-agent` was projected first, and a later Kubernetes sighting of the researcher attached onto that row. The original researcher row still exists. New researcher sightings update the attached row, not the original one.
- Certified digests are empty. The publish path must not certify a revision that has no digest. Enforce publication also refuses unless every target digest supports the required controls, which these digests do not.

### Integration with the UI

- The unfiltered Cloud Agents and Identities lists are still AWS-shaped. The Kubernetes sample appears only because the AWS list is empty, or because the provider filter is set to Kubernetes.
- Cards on the sample graph say the account is not known. There is no AWS account on that neighbourhood, and no cloud connector was added for it.
- Some links still leave the console: an access-request row opens `/iga/access-requests/<id>`, which has no route, and the policy evidence drawer links to `/iga/audit-events`, `/iga/observations`, and `/iga/graph/workloads/<id>`, which are not registered. Policy tabs that are not in the detail page (`rules` is registered; `history` and `deployments` are not real tabs) show an unknown-tab panel rather than the evidence.
- Rollback and revoke controls can still render on a published policy without a completed handler. The Instances and Policy requests on an agent can collide on the same client name.

### Enforcement

- `IGA_V2_ENFORCE` stays off. Turning it on is a separate decision. Observe publication does not block traffic and does not install a NetworkPolicy.
- Desired bundles are not applied on the host while the collector rejects its credential. In-cluster actuation is not enabled.
- Quarantine does not remove or isolate a running workload.
- The local demo's published researcher policy is observe only. It should not be reset or re-drafted as part of bringing enforcement up.

## Local demo, as left

Sign-in is `http://localhost:3000/admin/login`. The API is on port 7468 and the gateway on port 8088. Ingest, policy, ITDR, and graph projection are on. Enforcement is off. The kind workloads `langchain-sample-agent`, `authsec-iga-agent`, and the payments invoice deployments are up; `invoice-worker-idle` is scaled to zero. The host collector is the service that is not staying up.
