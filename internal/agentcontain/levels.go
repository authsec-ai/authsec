package agentcontain

import (
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsbroker"
	"github.com/authsec-ai/authsec/internal/igagov"
)

// The SecOps W2 stop levels (SPEC-secops-backend-upgrade.md P13, C8, C9) and
// proof states (P4).
//
// What each level enforces, and what it cannot (binding; the preview states
// the same as side effects):
//
//   - key: one access key of an IAM user set Inactive. Never undone
//     (DECISION P3-4a): release leaves it Inactive. Temporary credentials
//     already issued from the key (GetSessionToken, GetFederationToken: up to
//     36 h) are NOT revoked by deactivating it; contain the user at the
//     identity or sessions_before level for those.
//   - sessions_before: R2's aws:TokenIssueTime deny alone. It refuses every
//     temporary credential issued before the stop; new sessions work, and an
//     IAM user's long-term access keys are untouched (a long-term key carries
//     no aws:TokenIssueTime).
//   - chain: for a role, an AuthSec deny of sts:AssumeRole (with TagSession
//     and SetSourceIdentity) on the role, attached to each SAME-ACCOUNT role
//     or user its trust policy names, plus the session revocation on the role
//     itself (sessions the chain already opened). AWS cannot enforce more
//     without editing the role's trust policy, which AuthSec never does (the
//     trust policy is the customer's; iam:UpdateAssumeRolePolicy is not in
//     the enforcement template):
//     - an AWS service principal assumes with the service's own authority;
//     - another account's principals are governed by that account's IAM;
//     - a trust naming an account (root or "*") admits any principal of it
//     whose own policy allows the call: only the named assumers are denied;
//     - federation (AssumeRoleWithWebIdentity / AssumeRoleWithSAML) is
//     authorised by the trust policy alone: there is no caller identity to
//     attach a deny to, and a deny on the role governs what its sessions do,
//     not who may assume it. Such sessions stay possible; the preview says
//     so and offers the identity level instead.
//   - source_identity: on a role AuthSec's broker assumes, a deny of every
//     action conditioned on aws:SourceIdentity matching the agent
//     (awsbroker.AgentSourcePattern), plus one conditioned on the
//     authsec-agent session tag for sessions opened before the SourceIdentity
//     carried the agent. Only sessions the broker opened are stopped:
//     anything else on the role (another workload, a session opened another
//     way) is not.
//   - entra: the service principal (or agent identity) disabled through
//     Microsoft Graph (accountEnabled=false) and its Azure role assignments
//     removed (recorded, restored on release). Access tokens already issued
//     stay valid until they expire (token_expiry_at): the stop is unproven
//     until then.
//   - kubernetes: the ServiceAccount taken out of every RoleBinding and
//     ClusterRoleBinding AuthSec has seen name it, through the in-cluster
//     agent (remove_binding_subject). RBAC is evaluated per request, so its
//     existing tokens lose those permissions at once; the tokens themselves
//     stay valid (the agent has no instruction to delete or rotate token
//     Secrets), and access through groups (system:serviceaccounts,
//     system:authenticated) or other paths is unchanged.
//   - gateway: a row only. The gateway refuses the subject from the deny
//     list it is handed (ActiveGatewayStops); AuthSec writes nothing to the
//     customer.
//   - platform: a stop AuthSec cannot write (a model provider, a SaaS
//     platform): recorded in state requested and asked of whoever can
//     (agent.ask_needed; the ask itself is W4).

// W2 levels.
const (
	LevelKey            = "key"
	LevelSessionsBefore = "sessions_before"
	LevelChain          = "chain"
	LevelSourceIdentity = "source_identity"
	LevelEntra          = "entra"
	LevelKubernetes     = "kubernetes"
	LevelGateway        = "gateway"
	LevelPlatform       = "platform"
)

// AWSLevels are the levels BuildPreview computes for an AWS identity, in the
// order the preview lists them.
var AWSLevels = []string{LevelWorkload, LevelModel, LevelIdentity, LevelKey, LevelSessionsBefore, LevelChain, LevelSourceIdentity}

// Families: which engine runs a level.
const (
	FamilyAWS        = "aws"
	FamilyEntra      = "entra"
	FamilyKubernetes = "kubernetes"
	// FamilyRecord levels write nothing to the customer (gateway, platform).
	FamilyRecord = "record"
)

// FamilyOf is the family of a level.
func FamilyOf(level string) string {
	switch level {
	case LevelEntra:
		return FamilyEntra
	case LevelKubernetes:
		return FamilyKubernetes
	case LevelGateway, LevelPlatform:
		return FamilyRecord
	}
	return FamilyAWS
}

// Identity kinds beyond IAM (agent_containment.identity_kind).
const (
	IdentityEntraSP       = "entra_service_principal"
	IdentityEntraAgent    = "entra_agent_identity"
	IdentityK8sSA         = "k8s_service_account"
	IdentityGatewayAgent  = "gateway_agent"
	IdentityPlatformAgent = "platform_principal"
)

// W2 step kinds.
const (
	StepAssumerPolicy       = "assumer_policy"
	StepEntraAccount        = "entra_account"
	StepAzureRoleAssignment = "azure_role_assignment"
	StepK8sBindingSubject   = "k8s_binding_subject"
)

// W2 refusal codes.
const (
	RefuseNoAccessKey               = "access_key_required"
	RefuseKeyNeedsUser              = "key_level_needs_iam_user"
	RefuseChainNeedsRole            = "chain_level_needs_role"
	RefuseChainNothingEnforceable   = "chain_nothing_enforceable"
	RefuseSourceIdentityNeedsRole   = "source_identity_needs_role"
	RefuseSourceIdentityNoAgent     = "agent_required"
	RefuseSourceIdentityNotBrokered = "source_identity_unavailable"
	RefuseLevelNotForIdentity       = "level_not_for_identity"
	RefusePermissionMissing         = "permission_missing"
	RefuseManagedIdentity           = "managed_identity_not_disableable"
	RefuseK8sNoBinding              = "k8s_no_binding"
	RefuseK8sAgentCannotAct         = "k8s_agent_cannot_act"
)

// W2 side-effect codes.
const (
	EffectKeySessionsLive        = "session_tokens_from_key_stay_valid"
	EffectKeyNoUndo              = "access_key_never_reactivated"
	EffectNewSessionsWork        = "new_sessions_work"
	EffectLongTermKeysUnchanged  = "long_term_keys_unchanged"
	EffectChainNotEnforceable    = "chain_part_not_enforceable"
	EffectChainAssumersDenied    = "assumers_lose_assume_role"
	EffectOtherAgentsWork        = "other_agents_on_role_work"
	EffectNotBrokeredNotStopped  = "sessions_not_opened_by_authsec_not_stopped"
	EffectTokensLiveUntilExpiry  = "issued_tokens_live_until_expiry"
	EffectRoleAssignmentsRemoved = "role_assignments_removed"
	EffectK8sTokensValid         = "k8s_tokens_stay_valid"
	EffectK8sOtherPaths          = "k8s_other_paths_unchanged"
	EffectGatewayOnly            = "gateway_calls_only"
	EffectNothingWritten         = "nothing_written"
)

// Proof states (agent_containment.proof_state, P4): requested -> applied
// -> proven | unproven | cannot_verify -> kept.
const (
	ProofRequested    = "requested"     // not (yet) in place
	ProofApplied      = "applied"       // in place and read back; no verdict yet
	ProofProven       = "proven"        // a refusal naming the stop proves it (event or probe)
	ProofUnproven     = "unproven"      // waiting past the window, timed out, or a call succeeded
	ProofCannotVerify = "cannot_verify" // no event can prove this stop (final)
	ProofKept         = "kept"          // released, but something is deliberately left (a key, a revocation)
)

// ProofInput is what decides a containment's proof state.
type ProofInput struct {
	Level string
	State string
	// Effective / Verified are agent_containment.effective / verified_at.
	Effective *bool
	Verified  bool
	// Unverifiable is verification.unverifiable recorded; Final its final flag.
	Unverifiable      bool
	UnverifiableFinal bool
	// Kept: released, with an access key left Inactive (never reactivated)
	// or a session revocation still in place until its time.
	Kept        bool
	TokenExpiry *time.Time
	Now         time.Time
}

// ProofStateOf is the proof state (migration 193 backfills the same rule).
// Silence is never proof: a containment no refusal has proven stays applied
// (in place, waiting), then unproven when its wait ends without proof, or
// cannot_verify when no event can ever prove it. An Entra stop is unproven
// until every token issued before it has expired.
func ProofStateOf(in ProofInput) string {
	switch in.State {
	case StatePreviewed, StateRequested, StateContaining, StateFailed:
		return ProofRequested
	}
	if in.State == StateReleased && in.Kept {
		return ProofKept
	}
	switch {
	case in.Verified && in.Effective != nil && *in.Effective:
		return ProofProven
	case in.Effective != nil && !*in.Effective:
		return ProofUnproven
	case in.Unverifiable && in.UnverifiableFinal:
		return ProofCannotVerify
	case in.Unverifiable:
		return ProofUnproven
	case in.State == StateReleased:
		return ProofUnproven
	}
	if in.Level == LevelEntra && in.TokenExpiry != nil && in.Now.Before(*in.TokenExpiry) {
		return ProofUnproven
	}
	return ProofApplied
}

// Credential lifetimes behind token_expiry_at.
const (
	// UserSessionMax is the longest temporary credential an IAM user can
	// hold (GetSessionToken / GetFederationToken: 36 hours).
	UserSessionMax = 36 * time.Hour
	// EntraTokenMax is the default upper bound of an Entra access token's
	// lifetime (60-90 minutes, randomised). Continuous-access-evaluation
	// tokens can live longer (up to 28 h) where the resource supports CAE;
	// app-only tokens of a service principal do not get them by default.
	EntraTokenMax = 90 * time.Minute
	// K8sProjectedTokenDefault is a projected ServiceAccount token's default
	// expirationSeconds (3600). A legacy token Secret never expires.
	K8sProjectedTokenDefault = time.Hour
)

// TokenExpiryAt is the latest time a credential issued before the stop
// (cutoff) can still be live, nil when the level stops no credential (the
// workload level stops compute; gateway and platform write nothing).
// Role sessions: IAM's maximum session (12 h) plus R2's hour of margin
// (RevokeRemoveAfter).
func TokenExpiryAt(level, identityKind string, cutoff time.Time) *time.Time {
	var t time.Time
	switch level {
	case LevelIdentity, LevelModel, LevelSessionsBefore, LevelChain, LevelSourceIdentity:
		if identityKind == IdentityUser {
			t = cutoff.Add(UserSessionMax)
		} else {
			t = RevokeRemoveAfter(cutoff)
		}
	case LevelKey:
		t = cutoff.Add(UserSessionMax)
	case LevelEntra:
		t = cutoff.Add(EntraTokenMax)
	case LevelKubernetes:
		t = cutoff.Add(K8sProjectedTokenDefault)
	default:
		return nil
	}
	t = t.UTC()
	return &t
}

// Narrower reports whether `to` is a narrower stop than `from` on the same
// identity (POST .../narrow), and why not when it is not.
func Narrower(from, identityKind, to string) (bool, string) {
	allowed := map[string][]string{}
	switch identityKind {
	case IdentityRole:
		allowed[LevelIdentity] = []string{LevelModel, LevelWorkload, LevelSourceIdentity, LevelSessionsBefore}
		allowed[LevelChain] = []string{LevelSessionsBefore}
	case IdentityUser:
		allowed[LevelIdentity] = []string{LevelKey, LevelModel, LevelSessionsBefore}
	}
	for _, l := range allowed[from] {
		if l == to {
			return true, ""
		}
	}
	return false, "a " + to + " stop is not narrower than a " + from + " stop of this identity"
}

/* ------------------------------- documents ------------------------------- */

// Sids and names of the W2 documents.
const (
	ChainPolicyPrefix = "AuthSecContainChain-"
	SidDenyAssume     = "AuthSecContainDenyAssume"
	SidDenyAgent      = "AuthSecContainDenyAgent"
	SidDenyAgentTag   = "AuthSecContainDenyAgentTag"
)

// ChainActions are what a chain stop denies an assumer on the role.
var ChainActions = []string{"sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"}

// ChainPolicyName is the assumer's policy: AuthSecContainChain-<assumer
// unique id>-<containment 8hex>.
func ChainPolicyName(assumerUniqueID string, containmentID uuid.UUID) string {
	return ChainPolicyPrefix + assumerUniqueID + "-" + Short(containmentID)
}

// ChainDocument denies the chain actions on the contained role.
func ChainDocument(roleARN string) (string, string, error) {
	acts := append([]string(nil), ChainActions...)
	sort.Strings(acts)
	return canonical(map[string]any{
		"Version": igagov.PolicyVersion20121017,
		"Statement": []any{map[string]any{
			"Sid": SidDenyAssume, "Effect": igagov.EffectDeny, "Action": acts, "Resource": roleARN,
		}},
	})
}

// SourceIdentityDocument denies every action to the agent's broker sessions:
// aws:SourceIdentity like authsec-*-a<agent>, and (sessions the broker
// opened before the SourceIdentity named the agent) the authsec-agent
// session tag.
func SourceIdentityDocument(agentRef string) (string, string, error) {
	return canonical(map[string]any{
		"Version": igagov.PolicyVersion20121017,
		"Statement": []any{
			map[string]any{"Sid": SidDenyAgent, "Effect": igagov.EffectDeny, "Action": "*", "Resource": "*",
				"Condition": map[string]any{"StringLike": map[string]any{"aws:SourceIdentity": awsbroker.AgentSourcePattern(agentRef)}}},
			map[string]any{"Sid": SidDenyAgentTag, "Effect": igagov.EffectDeny, "Action": "*", "Resource": "*",
				"Condition": map[string]any{"StringEquals": map[string]any{"aws:PrincipalTag/authsec-agent": awsbroker.AgentTag(agentRef)}}},
		},
	})
}

/* -------------------------------- assumers ------------------------------- */

// Assumer kinds (who a role's trust policy lets assume it).
const (
	AssumerRole      = IdentityRole
	AssumerUser      = IdentityUser
	AssumerService   = "aws_service"
	AssumerExternal  = "external_account"
	AssumerAccount   = "account"
	AssumerFederated = "federated"
)

// Assumer is one principal of a role's trust policy, as the chain level
// sees it.
type Assumer struct {
	EdgeID   uuid.UUID `json:"edge_id"`
	Kind     string    `json:"kind"`
	Subject  string    `json:"subject"` // verbatim trust principal
	ARN      string    `json:"arn,omitempty"`
	Name     string    `json:"name,omitempty"`
	UniqueID string    `json:"unique_id,omitempty"`
	// IdentityID is the assumer's cloud_identity row when it is one.
	IdentityID *uuid.UUID        `json:"identity_id,omitempty"`
	Tags       map[string]string `json:"-"`
	// Enforceable: AuthSec can attach the chain deny to it.
	Enforceable bool   `json:"enforceable"`
	Why         string `json:"why,omitempty"`
}

// principal is the assumer as the IAM entity a policy is attached to.
func (a Assumer) principal() Principal {
	return Principal{Kind: a.Kind, Name: a.Name, UniqueID: a.UniqueID}
}
