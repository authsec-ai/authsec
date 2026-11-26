package agentcontain

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// The W2 AWS levels of the preview (levels.go says what each enforces).

// w2Levels are the key, sessions_before, chain and source_identity options.
func w2Levels(in PreviewInput, idRef []Refusal) []LevelOption {
	return []LevelOption{keyLevel(in, idRef), sessionsBeforeLevel(in, idRef), chainLevel(in, idRef), sourceIdentityLevel(in, idRef)}
}

func newOption(level string, idRef []Refusal) LevelOption {
	return LevelOption{Level: level, Refusals: append([]Refusal{}, idRef...), Stops: []WorkloadRef{}, AlsoStops: []WorkloadRef{},
		SideEffects: []SideEffect{}, Steps: []PlannedStep{}}
}

// keyLevel: one access key of an IAM user set Inactive, never reactivated.
func keyLevel(in PreviewInput, idRef []Refusal) LevelOption {
	o := newOption(LevelKey, idRef)
	if in.Subject.Kind != IdentityUser {
		o.Refusals = append(o.Refusals, refusalf(RefuseKeyNeedsUser, "%s is not an IAM user: only an IAM user has access keys.", in.Subject.Name))
	}
	key := strings.TrimSpace(in.Target)
	if key == "" {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseNoAccessKey, Message: "Name the access key to stop (target: its access key id, AKIA...)."})
	}
	if !in.Cap.Workload {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseUserNeedsParameter,
			Message: "Deactivating an access key needs the enforcement stack's EnableWorkloadContainment=true: " +
				nonEmpty(in.Cap.WorkloadReason, "the parameter is not set") + "."})
	}
	o.Steps = append(o.Steps, PlannedStep{Kind: StepAccessKey, Target: nonEmpty(key, "<access key id>"),
		Detail: "Set access key " + nonEmpty(key, "<access key id>") + " of " + in.Subject.Name + " Inactive. Release never reactivates it: issue a new key."})
	o.SideEffects = append(o.SideEffects,
		SideEffect{Code: EffectKeyNoUndo, Message: "Stopping a key cannot be undone: release leaves it Inactive (it may have leaked). Anything else using this key stops until it is given a new key."},
		SideEffect{Code: EffectKeySessionsLive, Message: "Temporary credentials already issued from this key (sts:GetSessionToken / GetFederationToken, up to 36 hours) are NOT revoked by deactivating it; add the sessions_before level for those."})
	o.Summary = "Stops access key " + nonEmpty(key, "<access key id>") + " of " + in.Subject.Name + "; its other keys and sessions are unchanged."
	o.Offered = len(o.Refusals) == 0
	return o
}

// sessionsBeforeLevel: R2's aws:TokenIssueTime deny alone.
func sessionsBeforeLevel(in PreviewInput, idRef []Refusal) LevelOption {
	o := newOption(LevelSessionsBefore, idRef)
	userOrBinding(&o, in)
	name := revokeNameOrPlaceholder(in.Subject.UniqueID, in.ContainmentID)
	o.Steps = append(o.Steps, PlannedStep{Kind: StepSessionRevoke, Target: name,
		Detail: "Attach /authsec/" + name + " to " + in.Subject.Name + ": every temporary credential issued before the stop is refused. Release removes it."})
	o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectNewSessionsWork,
		Message: "Only credentials issued before the stop are refused: a new session (or a workload that simply assumes the role again) works."})
	if in.Subject.Kind == IdentityUser {
		o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectLongTermKeysUnchanged,
			Message: "The user's long-term access keys carry no token issue time and keep working; stop them with the key level."})
	}
	for _, w := range in.Workloads {
		o.Stops = append(o.Stops, refOf(w))
	}
	o.Summary = "Refuses every session of " + in.Subject.Name + " issued before the stop; new sessions work."
	o.Offered = len(o.Refusals) == 0
	return o
}

// chainLevel: deny sts:AssumeRole on the role to each same-account assumer,
// plus the session revocation on the role.
func chainLevel(in PreviewInput, idRef []Refusal) LevelOption {
	o := newOption(LevelChain, idRef)
	if in.Subject.Kind != IdentityRole {
		o.Refusals = append(o.Refusals, refusalf(RefuseChainNeedsRole, "%s is not a role: only a role is assumed through a chain.", in.Subject.Name))
	}
	if !in.Cap.Binding {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseBindingUnavailable,
			Message: "AuthSec cannot change IAM in this account: " + nonEmpty(in.Cap.BindingReason, "the enforcement binding is not verified on template v2") + "."})
	}
	enforceable := 0
	var notEnforceable []string
	for _, a := range in.Assumers {
		if a.Enforceable && a.Kind == AssumerUser && !in.Cap.Workload {
			a.Enforceable, a.Why = false, "attaching a policy to an IAM user needs EnableWorkloadContainment=true"
		}
		if !a.Enforceable {
			notEnforceable = append(notEnforceable, a.Subject+" ("+a.Why+")")
			continue
		}
		enforceable++
		name := ChainPolicyPrefix + a.UniqueID + "-<id>"
		if in.ContainmentID != uuid.Nil {
			name = ChainPolicyName(a.UniqueID, in.ContainmentID)
		}
		o.Steps = append(o.Steps, PlannedStep{Kind: StepAssumerPolicy, Target: name,
			Detail: "Attach /authsec/" + name + " to " + a.Name + " denying sts:AssumeRole (with TagSession, SetSourceIdentity) on " + in.Subject.Name + "."})
	}
	if enforceable == 0 {
		o.Refusals = append(o.Refusals, refusalf(RefuseChainNothingEnforceable,
			"No principal of %s's trust policy is a role or user of this account AuthSec can attach a deny to; contain the identity instead.", in.Subject.Name))
	}
	rname := revokeNameOrPlaceholder(in.Subject.UniqueID, in.ContainmentID)
	o.Steps = append(o.Steps, PlannedStep{Kind: StepSessionRevoke, Target: rname,
		Detail: "Attach /authsec/" + rname + " to " + in.Subject.Name + ": sessions the chain already opened are refused until 13 hours after the stop, also after release."})
	o.SideEffects = append(o.SideEffects,
		SideEffect{Code: EffectChainAssumersDenied, Message: fmt.Sprintf("%d assumer(s) lose sts:AssumeRole on %s; their other access is unchanged.", enforceable, in.Subject.Name)},
		SideEffect{Code: EffectSessionsRevoked, Message: "Every session of the role issued before the stop is refused until 13 hours after it, whoever opened it."})
	if len(notEnforceable) > 0 {
		o.SideEffects = append(o.SideEffects, SideEffect{Code: EffectChainNotEnforceable, Message: "AWS cannot stop these without editing the role's trust policy, which AuthSec never does, so they can still assume it: " +
			strings.Join(notEnforceable, "; ") + ". Federated sign-in (web identity, SAML) is authorised by the trust policy alone, an AWS service assumes with its own authority, and another account's principals answer to that account's IAM."})
	}
	o.Summary = fmt.Sprintf("Stops %d same-account assumer(s) from assuming %s and refuses its existing sessions.", enforceable, in.Subject.Name)
	o.Offered = len(o.Refusals) == 0
	return o
}

// sourceIdentityLevel: deny one agent's broker sessions on a shared role.
func sourceIdentityLevel(in PreviewInput, idRef []Refusal) LevelOption {
	o := newOption(LevelSourceIdentity, idRef)
	userOrBinding(&o, in)
	if in.Subject.Kind != IdentityRole {
		o.Refusals = append(o.Refusals, refusalf(RefuseSourceIdentityNeedsRole, "%s is not a role: a SourceIdentity is set on role sessions.", in.Subject.Name))
	}
	agent := strings.TrimSpace(in.Target)
	if agent == "" {
		o.Refusals = append(o.Refusals, Refusal{Code: RefuseSourceIdentityNoAgent, Message: "Name the agent to stop (target: its client id or SPIFFE id)."})
	}
	if !in.Brokered {
		o.Refusals = append(o.Refusals, refusalf(RefuseSourceIdentityNotBrokered,
			"%s is not a role AuthSec's broker opens sessions on, so no session carries an agent's SourceIdentity; contain the identity, or bind the role for brokered sessions.", in.Subject.Name))
	}
	name := policyNameOrPlaceholder(in.Subject.UniqueID, in.ContainmentID)
	o.Steps = append(o.Steps, PlannedStep{Kind: StepIAMPolicy, Target: name,
		Detail: "Attach /authsec/" + name + " to " + in.Subject.Name + " denying every action to sessions whose aws:SourceIdentity (or authsec-agent session tag) names " + nonEmpty(agent, "<agent>") + "."})
	o.SideEffects = append(o.SideEffects,
		SideEffect{Code: EffectOtherAgentsWork, Message: "Other agents and workloads on " + in.Subject.Name + " keep working."},
		SideEffect{Code: EffectNotBrokeredNotStopped, Message: "Only sessions AuthSec's broker opened for this agent are stopped: the agent reaching AWS another way (its own keys, another role) is not."})
	o.Summary = "Stops " + nonEmpty(agent, "<agent>") + "'s brokered sessions on " + in.Subject.Name + "; everything else on the role is unchanged."
	o.Offered = len(o.Refusals) == 0
	return o
}
