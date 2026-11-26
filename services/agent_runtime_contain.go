package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Agent containment API (SPEC-agent-runtime-visibility.md §5.8, §10):
//
//	POST /api/iga/v1/agent-runtime/containments/preview     {identity_id, workload_ids?}
//	POST /api/iga/v1/agent-runtime/containments             {identity_id, workload_ids?, level, reason}
//	GET  /api/iga/v1/agent-runtime/containments?state=
//	GET  /api/iga/v1/agent-runtime/containments/:id
//	POST /api/iga/v1/agent-runtime/containments/:id/release {reason}
//
// The workspace is the token's only; every identity, workload and
// containment is read in a transaction under row-level security for it, so
// another workspace's object is 404, exactly like a missing one. There is no
// approval (§10 Q6): a containment is queued on the policy job worker the
// moment it is requested.

// AgentContain is the containment service.
type AgentContain struct {
	db  *gorm.DB
	now func() time.Time
	// capability overrides the binding read (tests).
	capability func(ctx context.Context, tx *gorm.DB, ws, connectorID uuid.UUID) agentcontain.Capability
}

// NewAgentContain builds the service.
func NewAgentContain(db *gorm.DB) *AgentContain { return &AgentContain{db: db, now: time.Now} }

// WithClock replaces the clock (tests).
func (s *AgentContain) WithClock(now func() time.Time) *AgentContain {
	s.now = now
	return s
}

// WithCapability replaces the enforcement binding read (tests).
func (s *AgentContain) WithCapability(f func(ctx context.Context, tx *gorm.DB, ws, connectorID uuid.UUID) agentcontain.Capability) *AgentContain {
	s.capability = f
	return s
}

// Containment error codes.
const (
	GovCodeContainmentRefused = "containment_refused"
	GovCodeContainmentExists  = "containment_exists"
	GovCodeNotReleasable      = "containment_not_releasable"
)

// AgentContainPreviewRequest is POST /containments/preview.
type AgentContainPreviewRequest struct {
	IdentityID  string   `json:"identity_id"`
	WorkloadIDs []string `json:"workload_ids"`
	// Target: as AgentContainRequest.Target (key, source_identity).
	Target string `json:"target"`
}

// AgentContainRequest is POST /containments.
type AgentContainRequest struct {
	IdentityID  string   `json:"identity_id"`
	WorkloadIDs []string `json:"workload_ids"`
	Level       string   `json:"level"`
	Reason      string   `json:"reason"`
	// Target is what a level names within the identity: the access key id
	// (key), the agent's client id or SPIFFE id (source_identity), the
	// gateway subject id (gateway), the platform principal (platform).
	Target string `json:"target"`
	// CaseID, when set, makes the case the containment's first hold; an
	// automation identity must name an open case (W5, CheckStopCase).
	CaseID string `json:"case_id"`
}

// AgentContainReleaseRequest is POST /containments/:id/release.
type AgentContainReleaseRequest struct {
	Reason string `json:"reason"`
}

// AgentContainmentView is a containment with its steps (detail only).
type AgentContainmentView struct {
	AgentContainment
	Steps []AgentContainmentStep `json:"steps,omitempty"`
	// Holds are the cases holding the stop (detail only).
	Holds []AgentContainmentHold `json:"holds,omitempty"`
	// ReleaseRequests are its release requests (detail only).
	ReleaseRequests []AgentContainmentReleaseRequest `json:"release_requests,omitempty"`
}

// MaxContainReason bounds a reason's length.
const MaxContainReason = 2000

func parseIDs(raw []string, field string) ([]uuid.UUID, error) {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, r := range raw {
		id, err := uuid.Parse(strings.TrimSpace(r))
		if err != nil {
			return nil, GovBadParam(field, field+" must be uuids.")
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

/* --------------------------------- preview --------------------------------- */

// containInventory is what one preview reads from the database.
type containInventory struct {
	identity  models.CloudIdentity
	workloads []agentcontain.Workload
	usage     []agentcontain.ServiceUse
	cap       agentcontain.Capability
	assumers  []agentcontain.Assumer
	brokered  bool
}

// readInventory reads the identity, the workloads running as it, its recent
// services and the binding's capability, under RLS for ws. selected ids that
// name nothing in ws are 404 (another workspace's workload is never
// confirmed to exist).
func (s *AgentContain) readInventory(ctx context.Context, ws, identityID uuid.UUID, selected []uuid.UUID) (*containInventory, error) {
	inv := &containInventory{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var ids []models.CloudIdentity
		if err := tx.Where("workspace_id = ? AND id = ?", ws, identityID).Limit(1).Find(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 0 {
			return GovNotFound()
		}
		inv.identity = ids[0]
		var conns []models.CloudConnector
		if err := tx.Where("workspace_id = ? AND id = ?", ws, inv.identity.ConnectorID).Limit(1).Find(&conns).Error; err != nil {
			return err
		}
		if len(conns) == 0 || conns[0].Provider != models.CloudProviderAWS {
			return GovNotFound()
		}
		var wls []models.CloudWorkload
		if err := tx.Where("workspace_id = ? AND identity_id = ?", ws, identityID).Order("name, id").Find(&wls).Error; err != nil {
			return err
		}
		for _, w := range wls {
			inv.workloads = append(inv.workloads, agentcontain.Workload{ID: w.ID, Kind: w.RuntimeKind, NativeID: w.NativeID, Name: w.Name,
				Region: w.Region, Via: "runs_as", EventSourceMappings: -1})
		}
		// Every principal that may assume the identity is part of its blast
		// radius: k8s service accounts and EKS pod identities, but also other
		// identities, CI pipelines, external accounts, SAML/human federation
		// and AWS services. A service principal of the same compute a
		// runs_as workload already names (lambda.amazonaws.com for a Lambda
		// function) is that workload, not another one.
		have := map[string]bool{}
		for _, w := range inv.workloads {
			have[w.Kind] = true
		}
		var edges []models.CloudAssumeEdge
		if err := tx.Where("workspace_id = ? AND identity_id = ?", ws, identityID).Order("subject, id").Find(&edges).Error; err != nil {
			return err
		}
		for _, e := range edges {
			name := e.Subject
			if e.K8sRef != nil && *e.K8sRef != "" {
				name = *e.K8sRef
			}
			switch {
			case e.Mechanism == models.AssumeMechanismEKSPodIdentity:
				inv.workloads = append(inv.workloads, agentcontain.Workload{ID: e.ID, Kind: agentcontain.WorkloadEKSPod, NativeID: name,
					Name: name, Via: "eks_pod_identity", EventSourceMappings: -1})
			case e.SubjectKind == models.AssumeSubjectK8sSA:
				inv.workloads = append(inv.workloads, agentcontain.Workload{ID: e.ID, Kind: agentcontain.WorkloadEKSPod, NativeID: name,
					Name: name, Via: "irsa", EventSourceMappings: -1})
			default:
				if e.SubjectKind == models.AssumeSubjectCloudService && have[serviceWorkloadKind(e.Subject)] {
					continue
				}
				via := e.SubjectKind
				if via == "" {
					via = "assume_role"
				}
				inv.workloads = append(inv.workloads, agentcontain.Workload{ID: e.ID, Kind: agentcontain.WorkloadAssumer, NativeID: e.Subject,
					Name: name, Via: via, EventSourceMappings: -1})
			}
		}
		if len(selected) > 0 {
			var n int64
			if err := tx.Model(&models.CloudWorkload{}).Where("workspace_id = ? AND id IN ?", ws, selected).Count(&n).Error; err != nil {
				return err
			}
			var m int64
			if err := tx.Model(&models.CloudAssumeEdge{}).Where("workspace_id = ? AND id IN ?", ws, selected).Count(&m).Error; err != nil {
				return err
			}
			if int(n+m) < len(selected) {
				return GovNotFound()
			}
		}
		var usage []models.CloudUsage
		if err := tx.Where("workspace_id = ? AND identity_id = ?", ws, identityID).Find(&usage).Error; err != nil {
			return err
		}
		inv.usage = usageOf(usage)
		inv.cap = s.capabilityOf(ctx, tx, ws, inv.identity.ConnectorID)
		var err error
		if inv.assumers, err = containAssumersTx(tx, ws, inv.identity, edges); err != nil {
			return err
		}
		inv.brokered, err = containBrokeredTx(tx, ws, inv.identity.NativeID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return inv, nil
}

// serviceWorkloadKind is the workload kind an AWS service principal in a
// trust policy stands for ("" when it names no kind of workload).
func serviceWorkloadKind(principal string) string {
	switch strings.ToLower(strings.TrimSpace(principal)) {
	case "lambda.amazonaws.com":
		return agentcontain.WorkloadLambda
	case "ecs-tasks.amazonaws.com":
		return agentcontain.WorkloadECSTaskDef
	case "ec2.amazonaws.com":
		return agentcontain.WorkloadEC2
	}
	return ""
}

// usageOf turns cloud_usage rows into recent services: Access Advisor rows,
// and the CloudTrail model-call row with its other services (P1).
func usageOf(rows []models.CloudUsage) []agentcontain.ServiceUse {
	var out []agentcontain.ServiceUse
	for _, u := range rows {
		if u.Source == agentruntime.UsageSource && u.Service == agentruntime.UsageService {
			var m agentruntime.ModelCallUsage
			_ = json.Unmarshal(u.Attrs, &m)
			out = append(out, agentcontain.ServiceUse{Service: "bedrock", Source: u.Source, LastUsedAt: m.LastCallAt, Calls: m.Calls})
			for src, n := range m.OtherServices {
				out = append(out, agentcontain.ServiceUse{Service: strings.TrimSuffix(src, ".amazonaws.com"), Source: u.Source, Calls: n})
			}
			continue
		}
		out = append(out, agentcontain.ServiceUse{Service: u.Service, Source: u.Source, LastUsedAt: u.LastUsedAt})
	}
	return out
}

// capabilityOf is the account's binding read (template v2 and the
// workload_containment capability), in tx.
func (s *AgentContain) capabilityOf(ctx context.Context, tx *gorm.DB, ws, connectorID uuid.UUID) agentcontain.Capability {
	if s.capability != nil {
		return s.capability(ctx, tx, ws, connectorID)
	}
	return ContainCapabilityTx(ctx, tx, ws, connectorID)
}

// ContainCapabilityTx reads one account's containment capability from its
// enforcement binding: verified on template v2 with the grants capabilities
// (identity and model levels), and the workload_containment capability the
// self-test records for EnableWorkloadContainment.
func ContainCapabilityTx(ctx context.Context, tx *gorm.DB, ws, connectorID uuid.UUID) agentcontain.Capability {
	var c agentcontain.Capability
	if err := RequireEnforcementV2(ctx, tx, ws, connectorID, EnforcementFeatureGrants); err != nil {
		c.BindingReason = govMessage(err)
	} else {
		c.Binding = true
	}
	if err := RequireEnforcementV2(ctx, tx, ws, connectorID, awsenforce.FeatureWorkloadContainment); err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Code == GovCodeBindingCapabilityGone {
			c.WorkloadReason = "the enforcement stack was deployed without EnableWorkloadContainment=true, or its self-test has not proven it (" +
				strings.Join(anyStrings(ge.Detail["missing"]), "; ") + ")"
		} else {
			c.WorkloadReason = govMessage(err)
		}
	} else {
		c.Workload = true
	}
	return c
}

func anyStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func govMessage(err error) string {
	var ge *GovError
	if errors.As(err, &ge) {
		return ge.Message
	}
	return err.Error()
}

// subjectOf is the containment subject of an inventory identity, labelled by
// the agent runtime resolver when one is installed.
func subjectOf(ctx context.Context, ws uuid.UUID, id models.CloudIdentity) agentcontain.Subject {
	a := id.AWSAttrs()
	partition, _, _, account, _, _ := agentcontain.ARNParts(id.NativeID)
	s := agentcontain.Subject{IdentityID: id.ID, ConnectorID: id.ConnectorID, Kind: id.Kind, ARN: id.NativeID, Name: id.Name,
		UniqueID: a.UniqueID, Path: a.Path, AccountID: account, Partition: partition, Tags: a.Tags}
	if s.Name == "" {
		s.Name = agentcontain.IdentityNameOf(id.NativeID)
	}
	if s.Path == "" {
		s.Path = agentcontain.IdentityPathOf(id.NativeID)
	}
	if r := agentruntime.Resolver(); r != nil {
		how := agentruntime.AttributionSessionIssuer
		if id.Kind == agentcontain.IdentityUser {
			how = agentruntime.AttributionPrincipalARN
		}
		if sub, err := r.Resolve(ctx, ws, id.ConnectorID, agentruntime.Attribution{How: how, ARN: id.NativeID, UniqueID: a.UniqueID}); err == nil {
			s.Label = sub.Label
		}
	}
	return s
}

// live fills the selected workloads' live reads (discovery role): the ECS
// services of a task definition revision, a function's tags and event source
// mappings. A read
// that fails leaves the workload unread (the preview then refuses it or
// states less), never a guess.
func (s *AgentContain) live(ctx context.Context, ws, connectorID uuid.UUID, wls []agentcontain.Workload, selected []uuid.UUID) {
	acc := agentContainAccess()
	sel := map[uuid.UUID]bool{}
	for _, id := range selected {
		sel[id] = true
	}
	for i := range wls {
		w := &wls[i]
		if !sel[w.ID] || acc == nil {
			continue
		}
		switch w.Kind {
		case agentcontain.WorkloadECSTaskDef:
			region := w.Region
			if region == "" {
				_, _, region, _, _, _ = agentcontain.ARNParts(w.NativeID)
			}
			svcs, err := acc.ECSServicesOf(ctx, ws, connectorID, region, w.NativeID)
			if err == nil {
				w.ECSServices, w.ECSServicesRead = svcs, true
			}
		case agentcontain.WorkloadLambda:
			if tags, err := acc.FunctionTags(ctx, ws, connectorID, w.NativeID); err == nil {
				w.Tags, w.TagsRead = tags, true
			}
			if n, err := acc.EventSourceMappings(ctx, ws, connectorID, w.NativeID); err == nil {
				w.EventSourceMappings = n
			}
		}
	}
}

// preview computes the blast radius for (identity, selected) in ws.
func (s *AgentContain) preview(ctx context.Context, ws uuid.UUID, identity string, workloadIDs []string, target string, containmentID uuid.UUID) (*agentcontain.Preview, *containInventory, error) {
	identityID, err := uuid.Parse(strings.TrimSpace(identity))
	if err != nil {
		if strings.TrimSpace(identity) == "" {
			return nil, nil, GovBadParam("identity_id", "identity_id is required.")
		}
		return nil, nil, GovNotFound()
	}
	selected, err := parseIDs(workloadIDs, "workload_ids")
	if err != nil {
		return nil, nil, err
	}
	inv, err := s.readInventory(ctx, ws, identityID, selected)
	if err != nil {
		return nil, nil, err
	}
	s.live(ctx, ws, inv.identity.ConnectorID, inv.workloads, selected)
	p := agentcontain.BuildPreview(agentcontain.PreviewInput{Subject: subjectOf(ctx, ws, inv.identity), Workloads: inv.workloads,
		Selected: selected, Usage: inv.usage, Cap: inv.cap, ContainmentID: containmentID, Now: s.now().UTC(),
		Target: strings.TrimSpace(target), Assumers: inv.assumers, Brokered: inv.brokered})
	return &p, inv, nil
}

// Preview is POST /containments/preview: a read with a body (stores nothing).
func (s *AgentContain) Preview(ctx context.Context, ws uuid.UUID, req AgentContainPreviewRequest) (*agentcontain.Preview, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	p, _, err := s.preview(ctx, ws, req.IdentityID, req.WorkloadIDs, req.Target, uuid.Nil)
	return p, err
}

/* --------------------------------- contain --------------------------------- */

// Contain is POST /containments: recompute the preview, refuse a level that
// is not offered (422 with the refusals), record the containment (state
// previewed, with its preview) and queue its job. No approval (§10 Q6).
func (s *AgentContain) Contain(ctx context.Context, ws, actor uuid.UUID, req AgentContainRequest) (*AgentContainmentView, error) {
	return s.contain(ctx, ws, actor, req, nil)
}

// contain records a containment; narrowedFrom, when set, is the wider
// containment it replaces (Narrow), whose active holds it takes over.
func (s *AgentContain) contain(ctx context.Context, ws, actor uuid.UUID, req AgentContainRequest, narrowedFrom *uuid.UUID) (*AgentContainmentView, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	level := strings.TrimSpace(req.Level)
	if !agentcontain.ValidLevel(level) {
		return nil, GovBadParam("level", "level must be one of "+strings.Join(agentcontain.Levels, ", ")+".")
	}
	var caseID *uuid.UUID
	if c := strings.TrimSpace(req.CaseID); c != "" {
		id, err := uuid.Parse(c)
		if err != nil {
			return nil, GovBadParam("case_id", "case_id must be a uuid.")
		}
		caseID = &id
	}
	req.Target = strings.TrimSpace(req.Target)
	if len(req.Target) > 512 {
		return nil, GovBadParam("target", "target is too long.")
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return nil, GovBadParam("reason", "A containment needs a reason.")
	}
	if len(reason) > MaxContainReason {
		return nil, GovBadParam("reason", "reason is too long.")
	}
	if level != agentcontain.LevelWorkload && len(req.WorkloadIDs) > 0 {
		// Identity and model levels act on the identity: workloads are not
		// narrowed there, they are only shown as the blast radius.
		req.WorkloadIDs = nil
	}
	if agentcontain.FamilyOf(level) != agentcontain.FamilyAWS {
		return s.containOther(ctx, ws, actor, level, reason, req, caseID, narrowedFrom)
	}
	switch level {
	case agentcontain.LevelKey, agentcontain.LevelSourceIdentity:
	default:
		req.Target = ""
	}
	id := uuid.New()
	p, inv, err := s.preview(ctx, ws, req.IdentityID, req.WorkloadIDs, req.Target, id)
	if err != nil {
		return nil, err
	}
	opt := p.Level(level)
	if opt == nil || !opt.Offered {
		var refusals []agentcontain.Refusal
		if opt != nil {
			refusals = opt.Refusals
		}
		return nil, govUnprocessable(GovCodeContainmentRefused, "This identity cannot be contained at the "+level+" level.",
			map[string]any{"level": level, "refusals": refusals})
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Second)
	row := AgentContainment{ID: id, WorkspaceID: ws, ConnectorID: inv.identity.ConnectorID, IdentityID: inv.identity.ID,
		IdentityKind: inv.identity.Kind, IdentityARN: inv.identity.NativeID, UniqueID: p.Subject.UniqueID,
		WorkloadIDs: pq.StringArray{}, Level: level, State: agentcontain.StatePreviewed, Reason: reason, CreatedBy: actor,
		Verification: json.RawMessage(`{}`), Preview: raw, CreatedAt: now, UpdatedAt: now,
		ProofState: agentcontain.ProofRequested, Target: req.Target, NarrowedFrom: narrowedFrom,
		TokenExpiryAt: agentcontain.TokenExpiryAt(level, inv.identity.Kind, now)}
	if level == agentcontain.LevelWorkload {
		for _, w := range p.Selected {
			row.WorkloadIDs = append(row.WorkloadIDs, w.String())
		}
	}
	err = s.recordContainment(ctx, ws, actor, &row, caseID, map[string]any{
		"workload_ids": row.WorkloadIDs, "stops": opt.Stops, "also_stops": opt.AlsoStops,
		"side_effects": opt.SideEffects, "steps": opt.Steps, "label": p.Subject.Label,
	})
	if err != nil {
		return nil, err
	}
	return &AgentContainmentView{AgentContainment: row}, nil
}

// recordContainment inserts the row (one live per identity, level and
// target), its first hold, the requested event, the narrowed-from holds and
// its job, in one transaction under RLS for ws.
func (s *AgentContain) recordContainment(ctx context.Context, ws, actor uuid.UUID, row *AgentContainment, caseID *uuid.UUID, extra map[string]any) error {
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if caseID != nil {
			if err := requireCaseTx(tx, ws, *caseID); err != nil {
				return err
			}
		}
		var live []AgentContainment
		if err := tx.Where("workspace_id = ? AND identity_id = ? AND level = ? AND target = ? AND state IN ?", ws, row.IdentityID, row.Level,
			row.Target, agentcontain.LiveStates).Limit(1).Find(&live).Error; err != nil {
			return err
		}
		if len(live) > 0 {
			return govConflict(GovCodeContainmentExists, "This identity already has a live containment at this level; release it first.",
				map[string]any{"containment_id": live[0].ID, "state": live[0].State})
		}
		if err := tx.Create(row).Error; err != nil {
			if isUniqueViolation(err, "uq_agent_containment_live") {
				return govConflict(GovCodeContainmentExists, "This identity already has a live containment at this level; release it first.", nil)
			}
			return err
		}
		kind, aid := userActor(actor)
		payload := map[string]any{"containment_id": row.ID, "identity_id": row.IdentityID, "identity_arn": row.IdentityARN,
			"level": row.Level, "target": row.Target, "reason": row.Reason}
		if row.NarrowedFrom != nil {
			payload["narrowed_from"] = *row.NarrowedFrom
		}
		if caseID != nil {
			payload["case_id"] = *caseID
		}
		for k, v := range extra {
			payload[k] = v
		}
		if err := appendGovEvent(tx, ws, GovEventContainmentRequested, kind, aid, govEventRefs{}, payload); err != nil {
			return err
		}
		if caseID != nil {
			if err := addHoldTx(tx, ws, row.ID, *caseID, actor, s.now().UTC()); err != nil {
				return err
			}
		}
		if row.NarrowedFrom != nil {
			if err := copyHoldsTx(tx, ws, *row.NarrowedFrom, row.ID, actor, s.now().UTC()); err != nil {
				return err
			}
		}
		if row.State == agentcontain.StateRequested {
			return appendGovEvent(tx, ws, GovEventAgentAskNeeded, kind, aid, govEventRefs{}, map[string]any{
				"containment_id": row.ID, "level": row.Level, "target": row.Target, "reason": row.Reason,
				"note": "AuthSec cannot stop this on the platform itself; whoever administers it must be asked to (W4 delivers the ask)."})
		}
		return enqueueContainTx(tx, ws, row.ID, row.CreatedAt)
	})
	if err != nil {
		return err
	}
	// The PDP refuses the agent from now on in this process (other
	// processes within their policy cache lifetime); gateways get it in
	// their next policy hints (AS-174).
	InvalidateAgentGatewayWorkspace(ws, uuid.Nil)
	return nil
}

// enqueueContainTx asks for the containment's job at `at`, pulling an open
// queued job forward (a release takes effect now, not at the next check).
func enqueueContainTx(tx *gorm.DB, ws, id uuid.UUID, at time.Time) error {
	sub := id
	key := "agent_containment:" + id.String()
	created, err := repositories.NewIGAGovJobRepository(tx).EnqueueTx(tx, &models.IGAGovJob{WorkspaceID: ws, Kind: GovJobAgentContain, SubjectID: &sub,
		DedupeKey: key, RunAfter: at})
	if err != nil || created {
		return err
	}
	return tx.Model(&models.IGAGovJob{}).
		Where("workspace_id = ? AND kind = ? AND dedupe_key = ? AND status = ? AND run_after > ?", ws, GovJobAgentContain, key, models.GovJobQueued, at).
		Update("run_after", at).Error
}

/* ---------------------------------- reads ---------------------------------- */

// List is GET /containments (?state, ?limit).
func (s *AgentContain) List(ctx context.Context, ws uuid.UUID, state string, limit int) ([]AgentContainmentView, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxGovPage {
		limit = 50
	}
	var states []string
	for _, x := range strings.Split(state, ",") {
		if x = strings.TrimSpace(x); x != "" {
			if !validContainState(x) {
				return nil, GovBadParam("state", "unknown state "+x+".")
			}
			states = append(states, x)
		}
	}
	var rows []AgentContainment
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Where("workspace_id = ?", ws)
		if len(states) > 0 {
			q = q.Where("state IN ?", states)
		}
		return q.Order("created_at DESC, id").Limit(limit).Find(&rows).Error
	})
	if err != nil {
		return nil, err
	}
	out := make([]AgentContainmentView, 0, len(rows))
	for _, r := range rows {
		out = append(out, AgentContainmentView{AgentContainment: r})
	}
	return out, nil
}

func validContainState(s string) bool {
	switch s {
	case agentcontain.StatePreviewed, agentcontain.StateRequested, agentcontain.StateContaining, agentcontain.StateContained, agentcontain.StatePartial,
		agentcontain.StateFailed, agentcontain.StateReleasing, agentcontain.StateReleased:
		return true
	}
	return false
}

// Get is GET /containments/:id with its steps.
func (s *AgentContain) Get(ctx context.Context, ws, id uuid.UUID) (*AgentContainmentView, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if err := RequireAgentContain(s.db); err != nil {
		return nil, err
	}
	var out *AgentContainmentView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := loadContainment(tx, ws, id, false)
		if err != nil {
			return err
		}
		steps, err := loadSteps(tx, ws, id)
		if err != nil {
			return err
		}
		out = &AgentContainmentView{AgentContainment: *row, Steps: steps}
		if err := tx.Where("workspace_id = ? AND containment_id = ?", ws, id).Order("held_at, id").Find(&out.Holds).Error; err != nil {
			return err
		}
		return tx.Where("workspace_id = ? AND containment_id = ?", ws, id).Order("requested_at DESC, id").Find(&out.ReleaseRequests).Error
	})
	return out, err
}

func loadContainment(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*AgentContainment, error) {
	q := tx.Where("workspace_id = ? AND id = ?", ws, id)
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var rows []AgentContainment
	if err := q.Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

func loadSteps(tx *gorm.DB, ws, id uuid.UUID) ([]AgentContainmentStep, error) {
	var steps []AgentContainmentStep
	if err := tx.Where("workspace_id = ? AND containment_id = ?", ws, id).Order("seq, id").Find(&steps).Error; err != nil {
		return nil, err
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].Seq < steps[j].Seq })
	return steps, nil
}

/* --------------------------------- release --------------------------------- */

// HoldsPermission is WorkspaceUserHoldsPermission under RLS for ws (the
// identity level's governance:emergency check).
func (s *AgentContain) HoldsPermission(ctx context.Context, ws, user uuid.UUID, resource, action string) (bool, error) {
	var ok bool
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		ok, err = WorkspaceUserHoldsPermission(tx, ws, user, resource, action)
		return err
	})
	return ok, err
}

/* ------------------------------- capabilities ------------------------------ */

// AgentContainAccountCapability is one AWS account's containment capability.
type AgentContainAccountCapability struct {
	ConnectorID         uuid.UUID `json:"connector_id"`
	AccountID           string    `json:"account_id"`
	Identity            bool      `json:"identity_and_model"`
	IdentityReason      string    `json:"identity_and_model_reason,omitempty"`
	WorkloadContainment bool      `json:"workload_containment"`
	WorkloadReason      string    `json:"workload_containment_reason,omitempty"`
}

// AgentContainCapabilities is /capabilities' agent_containment block for the
// token's workspace: the server (AgentContainStatus) and, per AWS account,
// the identity/model levels (verified template v2 binding) and the workload
// level (EnableWorkloadContainment, proven by the self-test), each with the
// reason when unavailable.
func AgentContainCapabilities(ctx context.Context, db *gorm.DB, ws uuid.UUID) map[string]any {
	ok, reason := AgentContainStatus(db)
	out := map[string]any{"available": ok, "reason": nullable(reason), "levels": agentcontain.Levels}
	accounts := []AgentContainAccountCapability{}
	anyWorkload, workloadReason := false, "No AWS account of this workspace has EnableWorkloadContainment=true proven by its enforcement self-test."
	if ws != uuid.Nil {
		_ = tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
			var conns []models.CloudConnector
			if err := tx.Where("workspace_id = ? AND provider = ?", ws, models.CloudProviderAWS).Order("scope_id").Find(&conns).Error; err != nil {
				return err
			}
			for _, c := range conns {
				cp := ContainCapabilityTx(ctx, tx, ws, c.ID)
				accounts = append(accounts, AgentContainAccountCapability{ConnectorID: c.ID, AccountID: c.ScopeID,
					Identity: cp.Binding, IdentityReason: cp.BindingReason, WorkloadContainment: cp.Workload, WorkloadReason: cp.WorkloadReason})
				anyWorkload = anyWorkload || cp.Workload
			}
			return nil
		})
	}
	wr := any(nil)
	if !anyWorkload {
		wr = workloadReason
	}
	if !ok {
		wr = reason
	}
	out["workload_containment"] = map[string]any{"available": ok && anyWorkload, "reason": wr}
	out["accounts"] = accounts
	return out
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// errContainNotConfigured is the job's wait while AWS access is missing.
var errContainNotConfigured = govErr(http.StatusServiceUnavailable, GovCodeContainUnavailable, "AWS access is not configured on this server.", nil)
