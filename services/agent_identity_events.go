package services

// iga_gov_event names written by W7 (one agent id, lifecycle, responder
// groups, classification, directory, hygiene). Listed in GovEventVocabulary
// under GovCatAgentLifecycle.
//
// agent.ask_needed stands in for an ask until W4 builds them: it names the
// agent, the reason and the subject a person must decide about.
// W4: every agent.ask_needed writer also raises an ask (agent_asks_needed.go).
const (
	GovCatAgentLifecycle = "agent_lifecycle"
	GovObjAgent          = "agent"

	GovEventAgentAskNeeded        = "agent.ask_needed"
	GovEventAgentRetired          = "agent.retired"
	GovEventAgentMerged           = "agent.merged"
	GovEventAgentTransferred      = "agent.transferred"
	GovEventAgentNotAnAgent       = "agent.not_an_agent"
	GovEventAgentDeletedAtSource  = "agent.deleted_at_source"
	GovEventAgentReappeared       = "agent.reappeared"
	GovEventAgentPurposeSet       = "agent.purpose_set"
	GovEventAgentRiskClassSet     = "agent.risk_class_set"
	GovEventAgentChangeRequested  = "agent.change_requested"
	GovEventAgentChangeApplied    = "agent.change_applied"
	GovEventAgentChangeRejected   = "agent.change_rejected"
	GovEventAgentChangeWithdrawn  = "agent.change_withdrawn"
	GovEventAgentChangeBreakGlass = "agent.change_break_glass"
	GovEventAgentInstanceNew      = "agent.instance_new"
	GovEventAgentUnknownDeployer  = "agent.instance_unknown_deployer"
	GovEventAgentDeployerAdded    = "agent.deployer_recorded"
	GovEventAgentStale            = "agent.stale"

	GovEventResourceClassified = "resource.classification_set"
	GovEventDirectoryLeft      = "directory.person_left"
	GovEventCredentialOverdue  = "credential.rotation_overdue"

	GovEventResponderGroupCreated   = "responder_group.created"
	GovEventResponderGroupUpdated   = "responder_group.updated"
	GovEventResponderGroupDeleted   = "responder_group.deleted"
	GovEventResponderMemberAssigned = "responder_group.member_assigned"
	GovEventResponderMemberRemoved  = "responder_group.member_removed"
	GovEventResponderMemberAccepted = "responder_group.member_accepted"
	GovEventResponderDelegated      = "responder_group.member_delegated"
	GovEventResponderScopeAdded     = "responder_group.scope_added"
	GovEventResponderScopeRemoved   = "responder_group.scope_removed"
	GovEventResponderHandover       = "responder_group.handover"
)

// Ask reasons carried by agent.ask_needed.
const (
	AskReasonDeletedAtSource = "deleted_at_source"
	AskReasonDeciderLeft     = "decider_left"
	AskReasonUnknownDeployer = "unknown_deployer"
)

var agentLifecycleVocabulary = []GovEventKind{
	{GovEventAgentAskNeeded, GovCatAgentLifecycle, GovObjAgent, "A person must decide about an agent (deleted at source, its only decider left, an unknown deployer, a platform stop AuthSec cannot write); an ask once W4 lands."},
	{GovEventAgentRetired, GovCatAgentLifecycle, GovObjAgent, "An agent was retired by a workspace member (reason given); every alias moved with it."},
	{GovEventAgentMerged, GovCatAgentLifecycle, GovObjAgent, "An agent was merged into another; its aliases now point at the survivor."},
	{GovEventAgentTransferred, GovCatAgentLifecycle, GovObjAgent, "An agent was transferred out of the workspace's responsibility (to whom, and why)."},
	{GovEventAgentNotAnAgent, GovCatAgentLifecycle, GovObjAgent, "A workspace member decided the object is not an agent (reason required on every source)."},
	{GovEventAgentDeletedAtSource, GovCatAgentLifecycle, GovObjAgent, "Every source of an agent reports it gone; the agent is marked deleted at source."},
	{GovEventAgentReappeared, GovCatAgentLifecycle, GovObjAgent, "An agent marked deleted at source was seen again and is active."},
	{GovEventAgentPurposeSet, GovCatAgentLifecycle, GovObjAgent, "A new version of an agent's purpose was recorded with its assessor."},
	{GovEventAgentRiskClassSet, GovCatAgentLifecycle, GovObjAgent, "A new risk class version was recorded (raised by its assessor, or lowered with a second person)."},
	{GovEventAgentChangeRequested, GovCatAgentLifecycle, "", "A tier-3 change (lowering a risk class or a resource classification) waits for a second person."},
	{GovEventAgentChangeApplied, GovCatAgentLifecycle, "", "A second person with governance:approve applied a pending tier-3 change."},
	{GovEventAgentChangeRejected, GovCatAgentLifecycle, "", "A second person rejected a pending tier-3 change."},
	{GovEventAgentChangeWithdrawn, GovCatAgentLifecycle, "", "The requester withdrew a pending tier-3 change."},
	{GovEventAgentChangeBreakGlass, GovCatAgentLifecycle, "", "The workspace's only approver applied a tier-3 lowering alone (break-glass); a review is due within 24 hours."},
	{GovEventAgentInstanceNew, GovCatAgentLifecycle, GovObjAgent, "A new instance (artifact digest or version) of an agent was observed."},
	{GovEventAgentUnknownDeployer, GovCatAgentLifecycle, GovObjAgent, "A new instance came from a deployer outside the agent's recorded deployer set."},
	{GovEventAgentDeployerAdded, GovCatAgentLifecycle, GovObjAgent, "A workspace member recorded a deployer for an agent."},
	{GovEventAgentStale, GovCatAgentLifecycle, GovObjAgent, "An agent made no call in 30 days on a source that sees its calls."},
	{GovEventResourceClassified, GovCatAgentLifecycle, "", "A resource's classification (sensitivity, crown jewel, data category, residency) was set by a person."},
	{GovEventDirectoryLeft, GovCatAgentLifecycle, "", "The directory reports a person left (SCIM or Entra)."},
	{GovEventCredentialOverdue, GovCatAgentLifecycle, "", "An IAM access key was last rotated more than 90 days ago."},
	{GovEventResponderGroupCreated, GovCatAgentLifecycle, "", "A responder group was created (or the workspace default with its admins)."},
	{GovEventResponderGroupUpdated, GovCatAgentLifecycle, "", "A responder group's name or description changed."},
	{GovEventResponderGroupDeleted, GovCatAgentLifecycle, "", "A responder group was deleted."},
	{GovEventResponderMemberAssigned, GovCatAgentLifecycle, "", "A person was assigned to a responder group as a candidate."},
	{GovEventResponderMemberRemoved, GovCatAgentLifecycle, "", "A person was removed from a responder group."},
	{GovEventResponderMemberAccepted, GovCatAgentLifecycle, "", "A candidate accepted their responder group membership."},
	{GovEventResponderDelegated, GovCatAgentLifecycle, "", "A member delegated their responder role to another person until an end date."},
	{GovEventResponderScopeAdded, GovCatAgentLifecycle, "", "A responder group took an estate scope (account, subscription, cluster, agent)."},
	{GovEventResponderScopeRemoved, GovCatAgentLifecycle, "", "A responder group gave up an estate scope."},
	{GovEventResponderHandover, GovCatAgentLifecycle, "", "A responder group handed all its scopes over to another group."},
}
