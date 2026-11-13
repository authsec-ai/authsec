package services

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

/* agent_runtime_findings.go is the risky-credential and identity findings of
   AI workloads on AWS (SPEC-agent-runtime-visibility.md §5.5, §5.2 step 3-4):

     shared_role        -- an AI workload's role has several workloads (or EKS
                           service accounts): the calls cannot be tied to one,
                           so no suggestion is made (§10 Q1)
     long_lived_key     -- model calls attributed to an IAM user: access keys,
                           with their age from cloud_secret
     human_credentials  -- model calls by a human or federated session: an IAM
                           Identity Center role or a SAML-federated role
     model_key_secret   -- a Secrets Manager secret whose NAME suggests a model
                           provider key, with the identities whose declared
                           grants let them read it; no value is ever read
     ai_config_hint     -- a workload whose configuration names a model
                           provider (agent_runtime_config_hints.go)
     ai_network_traffic -- written by the DNS evidence path, never here: read
                           only, it makes its identity an AI workload

   A finding is open while the newest inference of its connector sees it and
   resolved when it no longer does. Inference resolves only the kinds it
   writes (inferenceFindingKinds here, ai_config_hint in applyConfigHints). The
   three identity findings rest on model calls inside the last
   AgentRuntimeWindowDays days, so they resolve when the identity has made
   none in it. */

// FindingKinds are the kind filter's legal values.
var FindingKinds = map[string]bool{
	FindingSharedRole: true, FindingHumanCredentials: true, FindingLongLivedKey: true, FindingModelKeySecret: true,
	FindingAIConfigHint: true, FindingAINetworkTraffic: true,
}

// inferenceFindingKinds are the kinds applyFindings writes and resolves.
var inferenceFindingKinds = []string{FindingSharedRole, FindingHumanCredentials, FindingLongLivedKey, FindingModelKeySecret}

// FindingStates are the state filter's legal values.
var FindingStates = map[string]bool{FindingOpen: true, FindingResolved: true}

/* ----------------------------- model-key secrets ---------------------------- */

type modelKeySecret struct {
	ARN     string
	Name    string
	Region  string
	Readers []uuid.UUID // identities whose declared grants allow GetSecretValue
}

type modelKeySecrets struct {
	list []*modelKeySecret
	// known: the secret inventory was read for this connector, so a secret
	// absent from it is gone rather than unknown.
	known bool
}

func (m *modelKeySecrets) readableBy(identity uuid.UUID) []modelKeySecret {
	if m == nil {
		return nil
	}
	var out []modelKeySecret
	for _, s := range m.list {
		for _, r := range s.Readers {
			if r == identity {
				out = append(out, *s)
				break
			}
		}
	}
	return out
}

// arReadSecretAction is the action that reads a secret's value.
const arReadSecretAction = "secretsmanager:getsecretvalue"

// grantsSecretRead reports whether one of a statement's actions (IAM globs,
// case-insensitive) covers secretsmanager:GetSecretValue.
func grantsSecretRead(actions []string) bool {
	for _, a := range actions {
		if ok, _ := path.Match(strings.ToLower(a), arReadSecretAction); ok {
			return true
		}
	}
	return false
}

// loadModelKeySecrets reads the connector's Secrets Manager secret NAMES --
// from the newest scan whose resource-policy collection listed them
// (cloud_resource_policy_observation), and from the secrets a grant names
// (cloud_resource, newest generation) -- keeps the model-key-looking ones and
// the identities whose declared allow grants (cloud_permission; conditions
// stored, not evaluated) cover GetSecretValue on them.
func loadModelKeySecrets(tx *gorm.DB, ws uuid.UUID, conn arConnector) (*modelKeySecrets, error) {
	out := &modelKeySecrets{}
	byARN := map[string]*modelKeySecret{}
	add := func(arn, region string) {
		if arn == "" || byARN[arn] != nil {
			return
		}
		name := SecretNameFromARN(arn)
		if name == "" || !IsModelKeySecretName(name) {
			return
		}
		if region == "" {
			if parts := strings.Split(arn, ":"); len(parts) > 3 {
				region = parts[3]
			}
		}
		s := &modelKeySecret{ARN: arn, Name: name, Region: region}
		byARN[arn] = s
		out.list = append(out.list, s)
	}

	var latest []struct{ ScanRunID uuid.UUID }
	if err := tx.Table("cloud_resource_policy_coverage").Select("scan_run_id").
		Where("workspace_id = ? AND connector_id = ? AND resource_form = ? AND state IN ('complete','partial')",
			ws, conn.ID, "secretsmanager_secret").
		Order("collected_at DESC").Limit(1).Scan(&latest).Error; err != nil {
		return nil, fmt.Errorf("read secret coverage: %w", err)
	}
	if len(latest) == 1 {
		out.known = true
		var obs []struct {
			ResourceARN string
			Region      string
		}
		if err := tx.Table("cloud_resource_policy_observation").Select("resource_arn, region").
			Where("workspace_id = ? AND scan_run_id = ? AND resource_form = ?", ws, latest[0].ScanRunID, "secretsmanager_secret").
			Order("resource_arn").Scan(&obs).Error; err != nil {
			return nil, fmt.Errorf("read secrets: %w", err)
		}
		for _, o := range obs {
			add(o.ResourceARN, o.Region)
		}
	}

	var named []struct {
		ID       uuid.UUID
		NativeID string
	}
	if err := tx.Table("cloud_resource").Select("id, native_id").
		Where(`workspace_id = ? AND connector_id = ? AND kind = ? AND last_seen_generation =
			(SELECT COALESCE(MAX(r2.last_seen_generation), 0) FROM cloud_resource r2
			  WHERE r2.workspace_id = ? AND r2.connector_id = ?)`,
			ws, conn.ID, "secretsmanager_secret", ws, conn.ID).Scan(&named).Error; err != nil {
		return nil, fmt.Errorf("read named secrets: %w", err)
	}
	resourceARN := map[uuid.UUID]string{}
	for _, n := range named {
		resourceARN[n.ID] = n.NativeID
		add(n.NativeID, "")
	}
	if len(named) > 0 {
		out.known = true
	}
	if len(out.list) == 0 {
		return out, nil
	}

	// Who may read them: allow grants naming the secret, and account-wide
	// allow grants. Prefix grants are not resolved here (their pattern is not
	// stored per resource) and are left out rather than guessed.
	var grants []struct {
		IdentityID uuid.UUID
		ResourceID *uuid.UUID
		ScopeKind  string
		Actions    string
	}
	if err := tx.Table("cloud_permission").
		Select("identity_id, resource_id, scope_kind, array_to_string(actions, ',') AS actions").
		Where("workspace_id = ? AND connector_id = ? AND effect = 'allow' AND scope_kind IN ('resource','account_wide')",
			ws, conn.ID).Scan(&grants).Error; err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}
	for _, g := range grants {
		if !grantsSecretRead(strings.Split(g.Actions, ",")) {
			continue
		}
		switch g.ScopeKind {
		case "account_wide":
			for _, s := range out.list {
				s.Readers = arAppendUniqueUUID(s.Readers, g.IdentityID)
			}
		case "resource":
			if g.ResourceID == nil {
				continue
			}
			if s := byARN[resourceARN[*g.ResourceID]]; s != nil {
				s.Readers = arAppendUniqueUUID(s.Readers, g.IdentityID)
			}
		}
	}
	return out, nil
}

/* ------------------------------ the inference pass -------------------------- */

type findingDraft struct {
	Kind       string
	SubjectKey string
	IdentityID *uuid.UUID
	Subject    map[string]any
	Evidence   map[string]any
}

// isHumanSession: a role a person signs in to -- IAM Identity Center's
// reserved roles, or a role a SAML provider may assume.
func isHumanSession(ident *arIdentity, saml bool) bool {
	if ident.Kind != models.CloudIdentityIAMRole {
		return false
	}
	if saml {
		return true
	}
	return strings.Contains(ident.NativeID, ":role/aws-reserved/sso.amazonaws.com/") ||
		strings.HasPrefix(ident.Name, "AWSReservedSSO_")
}

// findingDrafts computes the connector's findings from the state.
func findingDrafts(tx *gorm.DB, ws uuid.UUID, st *agentRuntimeState, ais []*AIWorkload, secrets *modelKeySecrets, now time.Time) ([]findingDraft, error) {
	var out []findingDraft
	aiByIdentity := map[uuid.UUID]bool{}
	for _, ai := range ais {
		// A finding stands on model calls inside the evaluation window
		// (§5.3, §5.5): an identity with none in it raises none, and the
		// findings it had resolve.
		if !isAIWorkload(ai.win) {
			continue
		}
		aiByIdentity[ai.Identity.ID] = true
		id := ai.Identity.ID
		calls := map[string]any{"calls": ai.win.Calls, "denied": ai.win.Denied, "errors": ai.win.Errors,
			"models": arNonNil(ai.win.Models), "last_call_at": ai.LastCallAt,
			"window": ai.Coverage, "window_days": AgentRuntimeWindowDays}
		subject := map[string]any{"identity_id": id, "arn": ai.Identity.ARN, "name": ai.Identity.Name, "kind": ai.Identity.Kind}
		usageRefs := []uuid.UUID{}
		if ai.UsageID != uuid.Nil {
			usageRefs = append(usageRefs, ai.UsageID)
		}
		refs := map[string]any{"cloud_usage": usageRefs}
		if len(ai.NetworkTraffic) > 0 {
			ids := []uuid.UUID{}
			for _, n := range ai.NetworkTraffic {
				ids = append(ids, n.ID)
			}
			refs["agent_finding"] = ids
		}
		obs, err := cloudTrailObservations(tx, ws, id)
		if err != nil {
			return nil, fmt.Errorf("observations: %w", err)
		}
		refs["cloud_observation"] = nonNilUUIDs(obs)

		if ai.SharedRole {
			wls := []map[string]any{}
			for _, w := range ai.wls {
				wls = append(wls, map[string]any{"cloud_workload_id": w.ID, "workload_id": w.GraphID,
					"name": w.Name, "runtime_kind": w.RuntimeKind, "native_id": w.NativeID, "region": w.Region})
			}
			subj := cloneMap(subject)
			subj["workloads"] = wls
			subj["k8s_service_accounts"] = ai.K8sServiceAccounts
			out = append(out, findingDraft{Kind: FindingSharedRole, SubjectKey: ai.ident.subjectKey(), IdentityID: &id,
				Subject: subj, Evidence: map[string]any{"model_calls": calls, "references": refs,
					"candidates": len(ai.wls) + len(ai.K8sServiceAccounts),
					// Session names narrow nothing until verified (§10).
					"session_names": ai.SessionNames}})
		}
		switch {
		case ai.Identity.Kind == models.CloudIdentityIAMUser:
			keys, err := accessKeyEvidence(tx, ws, id, now)
			if err != nil {
				return nil, err
			}
			out = append(out, findingDraft{Kind: FindingLongLivedKey, SubjectKey: ai.ident.subjectKey(), IdentityID: &id,
				Subject: subject, Evidence: map[string]any{"model_calls": calls, "references": refs,
					"access_keys": keys, "credential": "iam_user"}})
		case isHumanSession(ai.ident, st.saml[id]):
			how := "identity_center"
			if st.saml[id] {
				how = "saml_federation"
			}
			out = append(out, findingDraft{Kind: FindingHumanCredentials, SubjectKey: ai.ident.subjectKey(), IdentityID: &id,
				Subject: subject, Evidence: map[string]any{"model_calls": calls, "references": refs, "session": how}})
		}
	}
	if secrets != nil {
		for _, s := range secrets.list {
			readers := []map[string]any{}
			for _, r := range s.Readers {
				readers = append(readers, map[string]any{"identity_id": r, "ai_workload": aiByIdentity[r]})
			}
			out = append(out, findingDraft{Kind: FindingModelKeySecret, SubjectKey: s.ARN,
				Subject: map[string]any{"arn": s.ARN, "name": s.Name, "region": s.Region},
				Evidence: map[string]any{"readers": readers, "readers_basis": "declared allow grants; conditions not evaluated",
					"value_read": false}})
		}
	}
	return out, nil
}

// accessKeyEvidence is an IAM user's access keys: id, status, age and last
// use, never a secret.
func accessKeyEvidence(tx *gorm.DB, ws, identity uuid.UUID, now time.Time) ([]map[string]any, error) {
	var keys []struct {
		ID         uuid.UUID
		NativeID   string
		Status     string
		CreatedAt  *time.Time
		LastUsedAt *time.Time
	}
	if err := tx.Table("cloud_secret").Select("id, native_id, status, created_at, last_used_at").
		Where("workspace_id = ? AND identity_id = ? AND kind = ?", ws, identity, models.CloudSecretAccessKey).
		Order("native_id").Scan(&keys).Error; err != nil {
		return nil, fmt.Errorf("read access keys: %w", err)
	}
	out := []map[string]any{}
	for _, k := range keys {
		var age any
		if k.CreatedAt != nil {
			age = int(now.Sub(*k.CreatedAt).Hours() / 24)
		}
		out = append(out, map[string]any{"cloud_secret_id": k.ID, "access_key_id": k.NativeID, "status": k.Status,
			"created_at": k.CreatedAt, "age_days": age, "last_used_at": k.LastUsedAt})
	}
	return out, nil
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// applyFindings opens or refreshes every finding the connector shows now and
// resolves its open findings that it no longer shows. Model-key-secret
// findings are resolved only when the secret inventory was read: an
// unreadable inventory is unknown, not empty.
func (s *AgentRuntimeService) applyFindings(tx *gorm.DB, ws, connectorID uuid.UUID, st *agentRuntimeState,
	ais []*AIWorkload, secrets *modelKeySecrets, now time.Time, res *AgentInferenceResult) error {
	drafts, err := findingDrafts(tx, ws, st, ais, secrets, now)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, d := range drafts {
		if err := upsertAgentFinding(tx, ws, connectorID, d, now); err != nil {
			return err
		}
		seen[d.Kind+"\x1f"+d.SubjectKey] = true
	}
	res.FindingsOpen = len(drafts)

	var open []struct {
		ID         uuid.UUID
		Kind       string
		SubjectKey string
		LastSeen   time.Time
	}
	// Only the kinds this pass writes: ai_config_hint has its own pass and
	// ai_network_traffic is another writer's.
	if err := tx.Table("agent_finding").Select("id, kind, subject_key, last_seen").
		Where("workspace_id = ? AND connector_id = ? AND state = ? AND kind IN ?", ws, connectorID, FindingOpen, inferenceFindingKinds).
		Scan(&open).Error; err != nil {
		return fmt.Errorf("read open findings: %w", err)
	}
	for _, f := range open {
		if seen[f.Kind+"\x1f"+f.SubjectKey] || findingKindsOutsideInference[f.Kind] {
			continue
		}
		if f.Kind == FindingModelKeySecret && (secrets == nil || !secrets.known) {
			continue
		}
		// The root finding is written by the evidence write, not drafted
		// here: it resolves once no root call is left in the window.
		if f.SubjectKey == rootFindingKey(connectorID) &&
			!f.LastSeen.Before(now.AddDate(0, 0, -AgentRuntimeWindowDays)) {
			continue
		}
		r := tx.Exec(`UPDATE agent_finding SET state = 'resolved', resolved_at = ?, updated_at = ?
			WHERE workspace_id = ? AND id = ? AND state = 'open'`, now, now, ws, f.ID)
		if r.Error != nil {
			return fmt.Errorf("resolve finding: %w", r.Error)
		}
		res.FindingsResolved += int(r.RowsAffected)
	}
	return nil
}

// upsertAgentFinding opens or refreshes one finding (one row per workspace,
// kind and subject key).
func upsertAgentFinding(tx *gorm.DB, ws, connectorID uuid.UUID, d findingDraft, now time.Time) error {
	subj, _ := json.Marshal(d.Subject)
	ev, _ := json.Marshal(d.Evidence)
	if err := tx.Exec(`INSERT INTO agent_finding
		  (workspace_id, connector_id, kind, subject_key, identity_id, subject, evidence, state,
		   first_seen, last_seen, resolved_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, 'open', ?, ?, NULL, ?, ?)
		ON CONFLICT (workspace_id, kind, subject_key) DO UPDATE SET
		  connector_id = excluded.connector_id, identity_id = excluded.identity_id,
		  subject = excluded.subject, evidence = excluded.evidence, state = 'open',
		  last_seen = excluded.last_seen, resolved_at = NULL, updated_at = excluded.updated_at`,
		ws, connectorID, d.Kind, d.SubjectKey, d.IdentityID, string(subj), string(ev), now, now, now, now).Error; err != nil {
		return fmt.Errorf("upsert finding %s: %w", d.Kind, err)
	}
	return nil
}

/* ---------------------------------- the reads ------------------------------- */

// AgentFinding is one finding as the API returns it.
type AgentFinding struct {
	ID          uuid.UUID       `json:"id"`
	ConnectorID *uuid.UUID      `json:"connector_id"` // NULL on a model provider finding (154)
	Kind        string          `json:"kind"`
	SubjectKey  string          `json:"subject_key"`
	IdentityID  *uuid.UUID      `json:"identity_id"`
	Subject     json.RawMessage `json:"subject"`
	Evidence    json.RawMessage `json:"evidence"`
	State       string          `json:"state"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	ResolvedAt  *time.Time      `json:"resolved_at"`
}

// FindingListFilter is GET /agent-runtime/findings's parameters.
type FindingListFilter struct {
	Kind        string
	State       string
	ConnectorID *uuid.UUID
	Cursor      string
	Limit       int
}

// ListFindings returns the workspace's findings, most recently seen first.
func (s *AgentRuntimeService) ListFindings(ctx context.Context, ws uuid.UUID, f FindingListFilter) ([]AgentFinding, *string, error) {
	if f.Kind != "" && !FindingKinds[f.Kind] {
		return nil, nil, GovBadParam("kind", "kind must be one of "+strings.Join(sortedKeys(FindingKinds), ", ")+".")
	}
	if f.State != "" && !FindingStates[f.State] {
		return nil, nil, GovBadParam("state", "state must be open or resolved.")
	}
	var after *arCursor
	if f.Cursor != "" {
		c, err := decodeARCursor(f.Cursor)
		if err != nil {
			return nil, nil, GovBadParam("cursor", "cursor is not one this server issued.")
		}
		after = c
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultAgentRuntimePage
	}
	var rows []AgentFinding
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Table("agent_finding").
			Select("id, connector_id, kind, subject_key, identity_id, subject, evidence, state, first_seen, last_seen, resolved_at").
			Where("workspace_id = ?", ws).
			// A revoked connector's findings stay for audit but are not listed.
			Where("connector_id NOT IN (SELECT id FROM cloud_connector WHERE workspace_id = ? AND status = ?)", ws, models.CloudConnectorRevoked)
		if f.Kind != "" {
			q = q.Where("kind = ?", f.Kind)
		}
		if f.State != "" {
			q = q.Where("state = ?", f.State)
		}
		if f.ConnectorID != nil {
			q = q.Where("connector_id = ?", *f.ConnectorID)
		}
		if after != nil {
			q = q.Where("(last_seen, id) < (?, ?)", after.At, after.ID)
		}
		return q.Order("last_seen DESC, id DESC").Limit(limit + 1).Scan(&rows).Error
	})
	if err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > limit {
		c := encodeARCursor(rows[limit-1].LastSeen, rows[limit-1].ID)
		next = &c
		rows = rows[:limit]
	}
	if rows == nil {
		rows = []AgentFinding{}
	}
	return rows, next, nil
}

func arAppendUniqueUUID(s []uuid.UUID, v uuid.UUID) []uuid.UUID {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
