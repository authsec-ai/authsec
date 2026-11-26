package services

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/awsbroker"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Active probes (SecOps P4): POST /containments/:id/probe.
//
// DECISION W2-4: a probe uses ONLY credentials AuthSec issues itself: a
// session AuthSec's R3 broker opens on the contained role (the role must be
// bound for brokered sessions, iga_gov_runtime_broker_role, and trust
// AuthSec's principal with the connector's ExternalId). Customer credentials
// are never used. The session's policy allows exactly one harmless read,
// s3:ListAllMyBuckets, which the containment's deny covers (identity level:
// Deny *; source_identity level: Deny * to the agent's sessions -- the probe
// session carries the agent's SourceIdentity and authsec-agent tag).
// sts:GetCallerIdentity is NOT used: no IAM deny applies to it. An
// AccessDenied whose message names the containment's own policy proves the
// stop, by the same rule as agentcontain.Proof; a success shows it is not in
// effect; any other answer proves nothing.
//
// Not probed (409 probe_not_possible, with why): an IAM user (AuthSec holds
// no credential of it), the model level (a harmless model call needs the
// Bedrock client: UNVERIFIED which read is harmless and denied), the
// sessions_before and chain levels (a probe session is issued after the
// cutoff, so the revocation does not apply to it), the workload, key,
// entra, kubernetes, gateway and platform levels (no AWS identity to act as).

// ContainProbeAction is the probe's call.
const ContainProbeAction = "s3:ListAllMyBuckets"

// ContainProbeCaller makes the probe's call with brokered credentials.
type ContainProbeCaller func(ctx context.Context, creds *awsbroker.Credentials, region string) error

var containProbe struct {
	sync.RWMutex
	call ContainProbeCaller
}

// SetContainProbeCaller replaces the probe call (tests); nil restores the
// live s3:ListBuckets. Returns a function restoring the previous one.
func SetContainProbeCaller(c ContainProbeCaller) (restore func()) {
	containProbe.Lock()
	prev := containProbe.call
	containProbe.call = c
	containProbe.Unlock()
	return func() { SetContainProbeCaller(prev) }
}

func currentContainProbeCaller() ContainProbeCaller {
	containProbe.RLock()
	defer containProbe.RUnlock()
	if containProbe.call != nil {
		return containProbe.call
	}
	return liveContainProbe
}

func liveContainProbe(ctx context.Context, creds *awsbroker.Credentials, region string) error {
	if region == "" {
		region = "us-east-1"
	}
	cfg := aws.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)}
	_, err := s3.NewFromConfig(cfg).ListBuckets(ctx, &s3.ListBucketsInput{})
	return err
}

// ContainProbeResult is the probe's answer.
type ContainProbeResult struct {
	Result      string               `json:"result"` // proven | not_effective | inconclusive
	Action      string               `json:"action"`
	Session     string               `json:"session_name"`
	Policy      string               `json:"policy,omitempty"`
	ErrorCode   string               `json:"error_code,omitempty"`
	Detail      string               `json:"detail"`
	At          time.Time            `json:"at"`
	Containment AgentContainmentView `json:"containment"`
}

func probeNotPossible(why string) error {
	return govConflict(GovCodeProbeNotPossible, "AuthSec cannot probe this containment with a credential of its own: "+why, map[string]any{"reason": why})
}

// Probe is POST /containments/:id/probe.
func (s *AgentContain) Probe(ctx context.Context, ws, actor, id uuid.UUID) (*ContainProbeResult, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	var row *AgentContainment
	var role models.IGAGovRuntimeBrokerRole
	brokered := false
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if row, err = loadContainment(tx, ws, id, false); err != nil {
			return err
		}
		var roles []models.IGAGovRuntimeBrokerRole
		if err := tx.Where("workspace_id = ? AND role_arn = ? AND state = ?", ws, row.IdentityARN, "active").Limit(1).Find(&roles).Error; err != nil {
			return err
		}
		if len(roles) > 0 {
			role, brokered = roles[0], true
		}
		return nil
	}); err != nil {
		return nil, err
	}
	switch {
	case row.State != agentcontain.StateContained && row.State != agentcontain.StatePartial:
		return nil, probeNotPossible("the containment is " + row.State + ", not in place")
	case row.Level != agentcontain.LevelIdentity && row.Level != agentcontain.LevelSourceIdentity:
		return nil, probeNotPossible("a " + row.Level + " stop cannot be shown by a call AuthSec makes itself (a session AuthSec opens now is not one the stop is about, or there is no AWS identity to act as)")
	case row.IdentityKind != agentcontain.IdentityRole:
		return nil, probeNotPossible("AuthSec holds no credential of an IAM user and never uses a customer's")
	case !brokered:
		return nil, probeNotPossible("the role is not bound for AuthSec's broker (bind it for brokered sessions so AuthSec may assume it)")
	}
	deps := CurrentRuntimeBrokerDeps()
	if deps == nil || deps.Inputs == nil || deps.Broker == nil {
		return nil, probeNotPossible("the broker is not configured on this server")
	}
	in, err := deps.Inputs(ctx, ws, role.ConnectorID)
	if err != nil {
		return nil, probeNotPossible("the account's connector cannot be used: " + err.Error())
	}
	agentRef := "authsec-probe"
	if row.Level == agentcontain.LevelSourceIdentity {
		agentRef = row.Target
	}
	short := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	policy, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
		"Effect": "Allow", "Action": ContainProbeAction, "Resource": "*"}}})
	req := awsbroker.Request{RoleARN: row.IdentityARN, ExternalID: in.ExternalID, Region: in.Region, SessionName: "authsec-probe-" + short,
		SourceIdentity: awsbroker.BrokerSourceIdentity(actor.String(), agentRef), SessionPolicy: string(policy), DurationSeconds: 900,
		Tags: map[string]string{"authsec-agent": awsbroker.AgentTag(agentRef), "authsec-workspace": GovWorkspaceRef(ws),
			"authsec-probe": row.ID.String()}}
	creds, err := deps.Broker.Assume(ctx, req)
	if err != nil {
		return nil, probeNotPossible("sts:AssumeRole on the role was refused: " + err.Error())
	}
	callErr := currentContainProbeCaller()(ctx, creds, in.Region)
	now := s.now().UTC()
	res := &ContainProbeResult{Action: ContainProbeAction, Session: req.SessionName, At: now}
	c := containedOf(*row)
	switch {
	case callErr == nil:
		res.Result, res.Detail = "not_effective", "AWS allowed "+ContainProbeAction+" to a session of the contained role: the containment is not in effect."
	case awsenforce.IsAccessDenied(callErr):
		res.ErrorCode = awsenforce.ErrorCode(callErr)
		if p := agentcontain.ProbeProves(c, callErr.Error()); p != "" {
			res.Result, res.Policy = "proven", p
			res.Detail = "AWS refused " + ContainProbeAction + " naming the containment's policy " + p + "."
		} else {
			res.Result, res.Detail = "inconclusive", "AWS refused the call, but the refusal does not name the containment's policy."
		}
	default:
		res.Result, res.Detail = "inconclusive", "The call failed without an authorisation answer: "+callErr.Error()
	}
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		pl := map[string]any{"containment_id": id, "result": res.Result, "action": res.Action, "session_name": res.Session,
			"policy": res.Policy, "error_code": res.ErrorCode, "detail": res.Detail}
		raw, _ := json.Marshal(map[string]any{"probe": pl, "probed_at": now})
		set := map[string]any{"verification": gorm.Expr("verification || ?::jsonb", string(raw)), "updated_at": now}
		q := tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ?", ws, id)
		switch res.Result {
		case "proven":
			set["verified_at"], set["effective"], set["proven_by_event_id"], set["skew_ms"] = now, true, "probe:"+req.SessionName, int64(0)
			pr, _ := json.Marshal(map[string]any{"evidence": "probe", "proof": pl})
			set["verification"] = gorm.Expr("(verification - 'unverifiable') || ?::jsonb", string(pr))
			q = q.Where("effective IS NULL AND verified_at IS NULL")
		case "not_effective":
			set["effective"] = false
		}
		if err := q.Updates(set).Error; err != nil {
			return err
		}
		kind, aid := userActor(actor)
		if err := appendGovEvent(tx, ws, GovEventContainmentProbe, kind, aid, govEventRefs{}, pl); err != nil {
			return err
		}
		return refreshContainProofTx(tx, ws, id, now)
	})
	if err != nil {
		return nil, err
	}
	v, err := s.Get(ctx, ws, id)
	if err != nil {
		return nil, err
	}
	res.Containment = *v
	return res, nil
}

