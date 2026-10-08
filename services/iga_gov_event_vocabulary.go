package services

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The iga_gov_event vocabulary (T3.20; SPEC-iga-phase3-policy.md §7.8, §9.6):
// every event name a Phase 3 writer appends, its Logs category, and the
// object it is about. tests/integration/p3_events_test.go walks the Go
// source of package services and fails when a writer uses a name that is not
// listed here, or when a listed name has no writer.
//
// DECISION (T3.20, names): the spec defines no event names -- §9.6 names
// only the Logs categories -- so no existing name was renamed. The earlier
// writers use two styles ("evaluation_completed", "evidence_bundle_created"
// from T3.06/T3.06b; dotted "owners.set", "attempt.prepared",
// "enforcement_binding.bound" from T3.07-T3.09); renaming them would change
// rows already written and the tests that assert them, for no
// spec-defined target. New names (T3.12/T3.20) are dotted <object>.<verb>.

// Logs categories (§9.6). A category is "recorded" once a writer exists;
// the rest are listed so the Logs kind filter can show them as "Not recorded
// yet" (§9.6) instead of inventing samples.
const (
	GovCatOwnership         = "ownership"
	GovCatEvaluation        = "evaluation"
	GovCatEvidence          = "evidence"
	GovCatEnforcementSetup  = "enforcement_binding"
	GovCatDeploymentAttempt = "deployment_attempt"
	GovCatOwnerReview       = "owner_review"
	GovCatNotification      = "notification"
	GovCatSettings          = "settings"
	// Recorded by T3.11 / T3.13 (listed at integration, p3-wire).
	GovCatProposal     = "proposal"
	GovCatApproval     = "approval"
	GovCatAcceptance   = "acceptance"
	GovCatRevalidation = "revalidation"
	// Not recorded yet in this build (their tasks have not landed).
	GovCatRollout        = "rollout"
	GovCatVerification   = "verification"
	GovCatDrift          = "drift"
	GovCatUndo           = "undo"
	GovCatControlRemoval = "control_removal"
	GovCatLegacy         = "legacy_agent_policy"
)

// Event names written by T3.12 / T3.20.
const (
	GovEventReviewOpened    = "review.opened"
	GovEventReviewReopened  = "review.reopened"
	GovEventReviewResponded = "review.responded"
	GovEventReviewCompleted = "review.completed"
	GovEventReviewExcepted  = "review.excepted"
	GovEventReviewReminded  = "review.reminded"
	GovEventReviewCancelled = "review.cancelled"

	GovEventNotificationSent   = "notification.sent"
	GovEventNotificationFailed = "notification.failed"
	GovEventNotificationDead   = "notification.dead"

	GovEventSettingsUpdated        = "settings.updated"
	GovEventSettingsChannelsCopied = "settings.notification_channels_copied"
)

// GovEventKind is one vocabulary entry.
type GovEventKind struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	// Object is the object kind the event is about (the events API's
	// object_kind filter); "" when it is about the workspace.
	Object      string `json:"object"`
	Description string `json:"description"`
}

// GovEventVocabulary is every event name written today, by writer.
var GovEventVocabulary = []GovEventKind{
	// T3.07 ownership (iga_gov_ownership_service.go).
	{"owners.set", GovCatOwnership, GovObjWorkloadOrIdentity, "An object's manual owners were set or cleared."},
	{"owner.review_date_set", GovCatOwnership, GovObjOwner, "An owner's review date was set or cleared."},
	{"owner_rule.created", GovCatOwnership, GovObjOwnerRule, "An owner tag rule was created."},
	{"owner_rule.deleted", GovCatOwnership, GovObjOwnerRule, "An owner tag rule was deleted with the owners it assigned."},
	{"owner_rule.evaluated", GovCatOwnership, "", "Owner tag rules were applied (owners added and removed, unmatched tags)."},
	// T3.06 evaluation (iga_gov_evaluator.go).
	{"evaluation_completed", GovCatEvaluation, "", "Findings were evaluated for a publication."},
	{"evaluation_failed", GovCatEvaluation, "", "A publication's finding evaluation failed."},
	{"evaluation_superseded", GovCatEvaluation, "", "A publication's evaluation was skipped: a newer one exists."},
	// T3.06b evidence (iga_gov_targets.go).
	{"evidence_bundle_created", GovCatEvidence, GovObjEvidenceBundle, "An evidence bundle was built for a role."},
	// T3.09 enforcement binding (cloud_enforcement_binding_service.go).
	{EventEnforcementSessionStarted, GovCatEnforcementSetup, GovObjBinding, "An enforcement Quick Create session was started."},
	{EventEnforcementBound, GovCatEnforcementSetup, GovObjBinding, "The enforcement role was bound."},
	{EventEnforcementBindFailed, GovCatEnforcementSetup, GovObjBinding, "Binding the enforcement role failed."},
	{EventEnforcementSelfTest, GovCatEnforcementSetup, GovObjBinding, "The enforcement self-test ran."},
	{EventEnforcementRevoked, GovCatEnforcementSetup, GovObjBinding, "The enforcement binding was revoked."},
	// T3.08 write-ahead attempts (iga_gov_attempt_log.go).
	{"attempt.prepared", GovCatDeploymentAttempt, GovObjDeployment, "A mutating AWS call was prepared (nothing sent)."},
	{"attempt.dispatched", GovCatDeploymentAttempt, GovObjDeployment, "A mutating AWS call is being sent."},
	{"attempt.completed", GovCatDeploymentAttempt, GovObjDeployment, "AWS answered a mutating call (outcome, request id)."},
	{"attempt.unknown", GovCatDeploymentAttempt, GovObjDeployment, "A dispatched call has no recorded answer; the role is held."},
	{"attempt.abandoned", GovCatDeploymentAttempt, GovObjDeployment, "A prepared call was never sent and was abandoned."},
	{"attempt.resolved", GovCatDeploymentAttempt, GovObjDeployment, "An unknown attempt was resolved as applied or not applied."},
	// T3.12 owner review (iga_gov_owner_review_service.go).
	{GovEventReviewOpened, GovCatOwnerReview, GovObjReview, "An owner review was opened for a version's compiled plans."},
	{GovEventReviewReopened, GovCatOwnerReview, GovObjReview, "An owner review was reopened: the impact changed or a new owner appeared."},
	{GovEventReviewResponded, GovCatOwnerReview, GovObjReview, "An owner acknowledged, retained a service or objected."},
	{GovEventReviewCompleted, GovCatOwnerReview, GovObjReview, "Every owner responded and nothing blocks the review."},
	{GovEventReviewExcepted, GovCatOwnerReview, GovObjReview, "An approver let the review proceed without a missing owner or response."},
	{GovEventReviewReminded, GovCatOwnerReview, GovObjReview, "Non-responders were notified again."},
	{GovEventReviewCancelled, GovCatOwnerReview, GovObjReview, "The review was cancelled (version withdrawn)."},
	// T3.12 notifications (iga_gov_notify.go).
	{GovEventNotificationSent, GovCatNotification, GovObjNotification, "A notification was delivered."},
	{GovEventNotificationFailed, GovCatNotification, GovObjNotification, "A notification attempt failed; it will be retried."},
	{GovEventNotificationDead, GovCatNotification, GovObjNotification, "A notification failed for good (5 attempts, or a permanent error)."},
	// T3.11 authoring and compiling (iga_gov_authoring_service.go,
	// iga_gov_compile_service.go) and T3.13 approval
	// (iga_gov_approval_service.go); names as their writers chose them
	// (p3-wire: listed at integration).
	{"proposal_created", GovCatProposal, GovObjPolicy, "A proposal opened a policy and its first version (from findings, a template or Discovery context)."},
	{"policy_created", GovCatProposal, GovObjPolicy, "A Phase 3 policy was created."},
	{"policy_updated", GovCatProposal, GovObjPolicy, "A policy's name, purpose or owner changed."},
	{"policy_paused", GovCatProposal, GovObjPolicy, "A policy was paused (with a reason)."},
	{"policy_resumed", GovCatProposal, GovObjPolicy, "A paused policy was resumed (with a reason)."},
	{"policy_archived", GovCatProposal, GovObjPolicy, "A policy was archived; its open versions were withdrawn."},
	{"version_created", GovCatProposal, GovObjVersion, "A new policy version was created."},
	{"version_proposed", GovCatProposal, GovObjVersion, "A version's plans were compiled and it went to review."},
	{"plans_recompiled", GovCatProposal, GovObjVersion, "An in-review version was recompiled against newer evidence."},
	{"impact_changed", GovCatProposal, GovObjVersion, "Who or what a target's change affects changed after the version was proposed."},
	{"version_withdrawn", GovCatProposal, GovObjVersion, "A version was withdrawn (by its author, a newer draft, or the policy's archive)."},
	{"version_approved", GovCatApproval, GovObjVersion, "A version was approved."},
	{"version_rejected", GovCatApproval, GovObjVersion, "A version was rejected (with a reason)."},
	{"version_superseded", GovCatApproval, GovObjVersion, "An approved version was superseded by the approval of a newer one."},
	{"acceptance_recorded", GovCatAcceptance, GovObjVersion, "An approver accepted an unanalysed form or evidence gap, item by item."},
	{"plan_revalidated", GovCatRevalidation, GovObjVersion, "An approved plan was revalidated against newer evidence (unchanged, material change or blocked)."},
	{"approval_revoked", GovCatRevalidation, GovObjVersion, "A version's approval was revoked by a material change."},
	// T3.20 settings (iga_gov_settings_service.go).
	{GovEventSettingsUpdated, GovCatSettings, "", "Workspace policy settings were changed (switching to enforce carries a reason)."},
	{GovEventSettingsChannelsCopied, GovCatSettings, "", "Legacy notification channel addresses were copied into the Phase 3 settings."},
	// T3.16 deployments, verification, drift, undo and control removal
	// (iga_gov_deploy_*.go).
	{GovEventDeploymentStarted, GovCatDeploymentAttempt, GovObjDeployment, "A deployment started (authority checked, binding fresh)."},
	{GovEventDeploymentBlocked, GovCatDeploymentAttempt, GovObjDeployment, "A deployment stopped as blocked (live state, approval or evidence changed)."},
	{GovEventDeploymentFailed, GovCatDeploymentAttempt, GovObjDeployment, "A deployment failed (a terminal AWS answer)."},
	{GovEventDeploymentApplied, GovCatDeploymentAttempt, GovObjDeployment, "Every op was done and the readback matched; awaiting verification."},
	{GovEventLedgerSettled, GovCatDeploymentAttempt, GovObjDeployment, "Intended ledger rows of a stopped deployment were settled."},
	{GovEventUnknownReading, GovCatDeploymentAttempt, GovObjDeployment, "A reading of an unknown outcome was taken after settle_after."},
	{GovEventDeploymentUnresolved, GovCatDeploymentAttempt, GovObjDeployment, "An unknown outcome could not be resolved; the role stays held for the operator."},
	{GovEventDeploymentResolveReq, GovCatDeploymentAttempt, GovObjDeployment, "An operator chose how to resolve an unresolved outcome or a stuck deployment."},
	{GovEventDeploymentRequeued, GovCatDeploymentAttempt, GovObjDeployment, "An in-flight deployment had no job to move it; its job was queued again."},
	{GovEventDeploymentRecovered, GovCatDeploymentAttempt, GovObjDeployment, "An unresolved deployment was handed over to its successor atomically."},
	{GovEventAcceptObservedOpened, GovCatDeploymentAttempt, GovObjDeployment, "A version accepting the observed state was proposed; the role stays held."},
	{GovEventVerificationRecorded, GovCatVerification, GovObjDeployment, "Verification dimensions were recorded."},
	{GovEventDeploymentVerified, GovCatVerification, GovObjDeployment, "The deployment was verified (artifact and graph)."},
	{GovEventDeploymentSuperseded, GovCatVerification, GovObjDeployment, "A newer deployment on the role replaced this one's artifact."},
	{GovEventPostureChanged, GovCatVerification, GovObjDeployment, "A service's current posture outcome changed."},
	{GovEventFindingPostureStatus, GovCatVerification, GovObjFinding, "A finding followed its service's posture (resolved, mitigated, reopened)."},
	{GovEventValidationDeclared, GovCatVerification, GovObjDeployment, "A validation session and its expected outcomes were declared."},
	{GovEventHealthReported, GovCatVerification, GovObjDeployment, "An owner reported a problem or that the workload works."},
	{GovEventDeploymentDrifted, GovCatDrift, GovObjDeployment, "The deployed artifact changed outside AuthSec (never auto-reconciled)."},
	{GovEventDriftLateMutation, GovCatDrift, GovObjDeployment, "A change matching an earlier unknown request appeared after it."},
	{GovEventControlRoleGone, GovCatDrift, GovObjDeployment, "The controlled role was deleted or recreated; the control was retired."},
	{GovEventUndoRequested, GovCatUndo, GovObjDeployment, "An undo to the recorded before-state was requested."},
	{GovEventEmergencyUndo, GovCatUndo, GovObjDeployment, "An emergency undo was requested without an approval reference."},
	{GovEventDeploymentUndone, GovCatUndo, GovObjDeployment, "A deployment was undone (verified undo)."},
	{GovEventRoleOnlyRecoveryPlan, GovCatUndo, GovObjDeployment, "A role-only recovery plan was compiled for a blocked undo."},
	{GovEventControlRemovalReq, GovCatControlRemoval, GovObjPolicy, "Removing AuthSec control was requested (review, or emergency)."},
	{GovEventControlRemoved, GovCatControlRemoval, GovObjPolicy, "AuthSec control of a role ended; the control is retired."},
	// T3.14 Slack app (slack_integration_service.go, slack_integration_interactions.go).
	// DECISION: §9.6 names no Slack category; they are notification events.
	{GovEventSlackInstalled, GovCatNotification, "", "The Slack app was installed (or reinstalled) for the workspace."},
	{GovEventSlackSettings, GovCatNotification, "", "The Slack approvals channel was changed."},
	{GovEventSlackDisconnected, GovCatNotification, "", "Slack was disconnected: token revoked, member links removed."},
	{GovEventSlackUserLinked, GovCatNotification, "", "A Slack user was linked to a member (verified email or console confirmation)."},
	{GovEventSlackActionReceived, GovCatNotification, GovObjNotification, "An authenticated Slack action was received on a notice (before authorization)."},
	// T3.17 IaC sources (iga_gov_iac_source_service.go): delivery setup.
	{GovEventIaCSourceCreated, GovCatEnforcementSetup, GovObjConnector, "An IaC source (repository directory) was mapped to an AWS account."},
	{GovEventIaCSourceDeleted, GovCatEnforcementSetup, GovObjConnector, "An IaC source was removed."},
	{GovEventIaCPermissionRequest, GovCatEnforcementSetup, GovObjConnector, "The GitHub App was asked for contents and pull-request write on the installation."},
	// T3.17 IaC and export delivery (iga_gov_iac_delivery.go).
	{GovEventExportReady, GovCatDeploymentAttempt, GovObjDeployment, "An export deployment is awaiting the customer's apply."},
	{GovEventIaCPROpened, GovCatDeploymentAttempt, GovObjDeployment, "A pull request was opened for an iac_pr deployment."},
	{GovEventIaCChangedReview, GovCatDeploymentAttempt, GovObjDeployment, "The pull request's head moved after AuthSec opened it."},
	{GovEventIaCReviewed, GovCatDeploymentAttempt, GovObjDeployment, "The pull request received its first approving review (reviewed SHA recorded)."},
	{GovEventIaCMerged, GovCatDeploymentAttempt, GovObjDeployment, "The pull request was merged; the deployment awaits the customer's apply."},
	{GovEventIaCClosed, GovCatDeploymentAttempt, GovObjDeployment, "The pull request was closed without merging; the deployment failed."},
	{GovEventIaCBlocked, GovCatDeploymentAttempt, GovObjDeployment, "Blocked before anything was proposed: the live state conflicts with the plan, or the mapped source no longer renders the approved change."},
	{GovEventIaCApplyRun, GovCatDeploymentAttempt, GovObjDeployment, "The repository reported a check run or deployment for the merge commit."},
	{GovEventIaCApplyPending, GovCatVerification, GovObjDeployment, "The desired state is not (fully) visible in AWS yet, or became overdue."},
	{GovEventIaCAppliedOutside, GovCatVerification, GovObjDeployment, "Applied outside AuthSec, matched by role, attachment and document hash."},
	{GovEventIaCUnexpected, GovCatVerification, GovObjDeployment, "What was applied is not what was reviewed: failed with the diff."},
	// T3.15 rollout (iga_gov_rollout_service.go, iga_gov_rollout_jobs.go).
	{GovEventRolloutObservationStarted, GovCatRollout, GovObjVersion, "Observation of a version started (or restarted after it went back to draft)."},
	{GovEventRolloutObservationChecked, GovCatRollout, GovObjVersion, "A publication's activity evidence was read for an observing version."},
	{GovEventRolloutObservationCompleted, GovCatRollout, GovObjVersion, "Observation ended: observe_until passed and every target has a fresh report."},
	{GovEventRolloutReturnedToDraft, GovCatRollout, GovObjVersion, "A removed service was attempted during observation; the version went back to draft."},
	{GovEventRolloutCanaryStarted, GovCatRollout, GovObjDeployment, "The canary deployment of an approved, observed version was created."},
	{GovEventRolloutDeploymentCreated, GovCatRollout, GovObjDeployment, "The rollout created a deployment and queued it."},
	{GovEventRolloutDeploymentRefused, GovCatRollout, GovObjVersion, "The rollout could not create a target's deployment (approval, binding, mode or a change in flight)."},
	{GovEventRolloutGatesEvaluated, GovCatRollout, GovObjDeployment, "The canary's gates were evaluated."},
	{GovEventRolloutGateAccepted, GovCatAcceptance, GovObjDeployment, "An approver accepted a canary gate that could not be evaluated."},
	{GovEventRolloutPaused, GovCatRollout, GovObjVersion, "The rollout was paused (by a person, a failed gate or deployment, drift, or a return to draft)."},
	{GovEventRolloutResumed, GovCatRollout, GovObjVersion, "A paused rollout was resumed."},
	{GovEventRolloutExpanded, GovCatRollout, GovObjVersion, "The canary passed and the remaining targets' deployments were created."},
	{GovEventRolloutCompleted, GovCatRollout, GovObjVersion, "Every target of the rollout was verified."},
	{GovEventRolloutPartial, GovCatRollout, GovObjVersion, "The rollout finished with some targets failed or refused."},
	{GovEventRolloutUndone, GovCatRollout, GovObjVersion, "The rollout's applied change was undone."},
	{GovEventRolloutRefreshQueued, GovCatRollout, GovObjConnector, "A connector scan was queued so observation gets a fresh activity report."},
	{GovEventRolloutRemoveControlStarted, GovCatControlRemoval, GovObjVersion, "An approved remove_control version was started (no observation or canary)."},
}

// Object kinds the events API filters on.
const (
	GovObjPolicy             = "policy"
	GovObjVersion            = "version"
	GovObjDeployment         = "deployment"
	GovObjFinding            = "finding"
	GovObjReview             = "review"
	GovObjOwner              = "owner"
	GovObjOwnerRule          = "owner_rule"
	GovObjBinding            = "enforcement_binding"
	GovObjConnector          = "connector"
	GovObjEvidenceBundle     = "evidence_bundle"
	GovObjNotification       = "notification"
	GovObjWorkload           = "workload"
	GovObjIdentityAccount    = "identity_account"
	GovObjWorkloadOrIdentity = "workload|identity_account"
)

// govEventObjectFilters maps an object_kind to how an event names it: a
// column of iga_gov_event, or a payload key.
var govEventObjectFilters = map[string]struct{ column, payloadKey string }{
	GovObjPolicy:          {column: "policy_id"},
	GovObjVersion:         {column: "version_id"},
	GovObjDeployment:      {column: "deployment_id"},
	GovObjFinding:         {column: "finding_id"},
	GovObjReview:          {payloadKey: "review_id"},
	GovObjOwner:           {payloadKey: "owner_id"},
	GovObjOwnerRule:       {payloadKey: "rule_id"},
	GovObjBinding:         {payloadKey: "binding_id"},
	GovObjConnector:       {payloadKey: "connector_id"},
	GovObjEvidenceBundle:  {payloadKey: "bundle_id"},
	GovObjNotification:    {payloadKey: "notification_id"},
	GovObjWorkload:        {payloadKey: "object_id"},
	GovObjIdentityAccount: {payloadKey: "object_id"},
}

// GovEventObjectKinds lists the object kinds the events API accepts.
func GovEventObjectKinds() []string {
	out := make([]string, 0, len(govEventObjectFilters))
	for k := range govEventObjectFilters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// GovEventCategory is the Logs category of an event name ("" when the name
// is not in the vocabulary).
func GovEventCategory(name string) string {
	for _, k := range GovEventVocabulary {
		if k.Name == name {
			return k.Category
		}
	}
	return ""
}

// GovEventCategoryView is one Logs kind-filter entry.
type GovEventCategoryView struct {
	Category string   `json:"category"`
	Recorded bool     `json:"recorded"`
	Events   []string `json:"events"`
	// Reason says why an unrecorded category has no events (§9.6 "Not
	// recorded yet").
	Reason string `json:"reason,omitempty"`
}

var govUnrecordedCategories = []string{GovCatProposal, GovCatApproval, GovCatAcceptance, GovCatRevalidation,
	GovCatRollout, GovCatVerification, GovCatDrift, GovCatUndo, GovCatControlRemoval, GovCatLegacy}

// GovEventCategories is the Logs kind filter: every recorded category with
// its event names, then the categories with no writer in this build.
func GovEventCategories() []GovEventCategoryView {
	idx := map[string]int{}
	var out []GovEventCategoryView
	for _, k := range GovEventVocabulary {
		i, ok := idx[k.Category]
		if !ok {
			i = len(out)
			idx[k.Category] = i
			out = append(out, GovEventCategoryView{Category: k.Category, Recorded: true})
		}
		out[i].Events = append(out[i].Events, k.Name)
	}
	for _, c := range govUnrecordedCategories {
		if _, ok := idx[c]; ok {
			continue
		}
		out = append(out, GovEventCategoryView{Category: c, Recorded: false, Events: []string{},
			Reason: "Not recorded yet: the feature that writes these events is not in this build."})
	}
	return out
}

// govEventRefs are the event's object columns.
type govEventRefs struct {
	PolicyID, VersionID, DeploymentID, FindingID *uuid.UUID
}

// appendGovEvent appends one event in tx (the mutation's transaction).
func appendGovEvent(tx *gorm.DB, ws uuid.UUID, name, actorKind, actorID string, refs govEventRefs, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return repositories.NewIGAGovEventRepository(tx).AppendTx(tx, &models.IGAGovEvent{
		WorkspaceID: ws, Event: name, ActorKind: actorKind, ActorID: actorID,
		PolicyID: refs.PolicyID, VersionID: refs.VersionID, DeploymentID: refs.DeploymentID, FindingID: refs.FindingID,
		Payload: raw,
	})
}

// govRedactKeys are payload keys whose values never leave the server
// through the events API or its export (§7.8 "redacted payloads").
var govRedactKeys = []string{"secret", "token", "password", "credential", "external_id", "externalid",
	"signature", "authorization", "private_key"}

// govRedactKey reports whether a payload key is sensitive: a secret-like
// substring, or an email address field ("email", "*_email", "emails";
// not "email_enabled").
func govRedactKey(k string) bool {
	lk := strings.ToLower(k)
	for _, s := range govRedactKeys {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return lk == "email" || lk == "emails" || strings.HasSuffix(lk, "_email")
}

// RedactGovEventPayload returns payload with the value of every sensitive
// key (govRedactKey, at any depth) replaced by "[redacted]". An unparseable
// payload is returned as {"unreadable": true}.
func RedactGovEventPayload(payload json.RawMessage) json.RawMessage {
	if len(payload) == 0 {
		return json.RawMessage(`{}`)
	}
	var v any
	if err := json.Unmarshal(payload, &v); err != nil {
		return json.RawMessage(`{"unreadable":true}`)
	}
	out, err := json.Marshal(govRedactValue(v))
	if err != nil {
		return json.RawMessage(`{"unreadable":true}`)
	}
	return out
}

func govRedactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if govRedactKey(k) {
				t[k] = "[redacted]"
			} else {
				t[k] = govRedactValue(x)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = govRedactValue(t[i])
		}
		return t
	}
	return v
}
