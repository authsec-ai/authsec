package integration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// p3Gov is a Phase 3 workspace with the rows a deployment needs (T3.07 /
// T3.08 tests): a connector, a published scan (rev 1), an evidence bundle, a
// boundary document, two verified human members, and per "lane" a role
// identity with a policy, version, control, target, plan and approval -- one
// lane per deployment, because at most one deployment per role control is in
// flight (uq_iga_gov_deployment_inflight).
//
// Cleanup purges the workspace with authsec.workspace_purge = on (the only way
// iga_gov_event rows may be deleted), then the users and roles it created.
type p3Gov struct {
	t            *testing.T
	db           *gorm.DB
	ws           uuid.UUID
	author       uuid.UUID // a member; the author / actor
	authorMember uuid.UUID
	approver     uuid.UUID
	conn         uuid.UUID
	run          uuid.UUID
	bundle       uuid.UUID
	docHash      string
	users        []uuid.UUID
	roles        []uuid.UUID
	lanes        int
}

// p3Lane is one role under one policy, ready for a deployment.
type p3Lane struct {
	identity uuid.UUID
	roleID   string
	policy   uuid.UUID
	version  uuid.UUID
	control  uuid.UUID
	target   uuid.UUID
	plan     uuid.UUID
	approval uuid.UUID
}

func p3exec(t *testing.T, db *gorm.DB, q string, args ...any) {
	t.Helper()
	if err := db.Exec(q, args...).Error; err != nil {
		t.Fatalf("fixture: %v\n%s", err, q)
	}
}

func p3NewGov(t *testing.T, db *gorm.DB, name string) *p3Gov {
	t.Helper()
	g := &p3Gov{t: t, db: db, ws: uuid.New(), conn: uuid.New(), run: uuid.New(), bundle: uuid.New()}
	p3exec(t, db, `INSERT INTO workspaces (id,name,slug,owner_user_id,workspace_type,workspace_domain,email,status,created_at,updated_at)
		VALUES (?,?,NULL,?,'team',?,?,'active',NOW(),NOW())`, g.ws, name, g.ws, g.ws.String()+".test", g.ws.String()+"@test.local")
	t.Cleanup(g.cleanup)
	g.author, g.authorMember = g.member("author-"+g.ws.String()[:8]+"@p3own.test", "Asha Author", "active")
	g.approver, _ = g.member("approver-"+g.ws.String()[:8]+"@p3own.test", "Ari Approver", "active")
	p3exec(t, db, `INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref)
		VALUES (?, ?, 'aws', 'account', '111111111111', 'vault://p3own/a')`, g.conn, g.ws)
	p3exec(t, db, `INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at)
		VALUES (?, ?, ?, 1, 'published', now())`, g.run, g.ws, g.conn)
	p3exec(t, db, `INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
		VALUES (?, 1, now(), ?, jsonb_build_object('aws:111111111111', ?::text))`, g.ws, g.run, g.run.String())
	bundle := `{"sources":[{"kind":"aws_publication","rev":1,"trust":"trusted"}],"target":{"account_id":"111111111111"}}`
	p3exec(t, db, `INSERT INTO iga_gov_evidence_bundle (id, workspace_id, provider, trust, bundle_hash, canonical, facts)
		VALUES (?, ?, 'aws', 'trusted', 'sha256:' || encode(sha256(convert_to(?::text, 'UTF8')), 'hex'), ?, ?::jsonb)`,
		g.bundle, g.ws, bundle, bundle, bundle)
	doc := `{"Statement":[{"Effect":"Allow","NotAction":["sqs:*"],"Resource":"*"}],"Version":"2012-10-17"}`
	if err := db.Raw(`SELECT 'sha256:' || encode(sha256(convert_to(?::text, 'UTF8')), 'hex')`, doc).Scan(&g.docHash).Error; err != nil {
		t.Fatal(err)
	}
	p3exec(t, db, `INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document) VALUES (?, ?, ?, ?::jsonb)`,
		g.ws, g.docHash, doc, doc)
	return g
}

// member creates a user with an active (or given-status) membership.
func (g *p3Gov) member(email, name, status string) (user, membership uuid.UUID) {
	g.t.Helper()
	user, membership, role := uuid.New(), uuid.New(), uuid.New()
	p3exec(g.t, g.db, `INSERT INTO users (id, email, name, workspace_id) VALUES (?, ?, ?, ?)`, user, email, name, g.ws)
	p3exec(g.t, g.db, `INSERT INTO roles (id, name, workspace_id) VALUES (?, ?, ?)`, role, "p3own-"+role.String()[:8], g.ws)
	p3exec(g.t, g.db, `INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status) VALUES (?, ?, ?, ?, ?)`,
		membership, g.ws, user, role, status)
	g.users = append(g.users, user)
	g.roles = append(g.roles, role)
	return user, membership
}

func (g *p3Gov) cleanup() {
	_ = g.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SET LOCAL authsec.workspace_purge = 'on'`).Error; err != nil {
			return err
		}
		return tx.Exec(`DELETE FROM workspaces WHERE id = ?`, g.ws).Error
	})
	for _, u := range g.users {
		g.db.Exec(`DELETE FROM workspace_memberships WHERE user_id = ?`, u)
		g.db.Exec(`DELETE FROM users WHERE id = ?`, u)
	}
	for _, r := range g.roles {
		g.db.Exec(`DELETE FROM roles WHERE id = ?`, r)
	}
}

// identity inserts an AWS role identity with the given provider tags.
func (g *p3Gov) identity(name string, tags map[string]string) (uuid.UUID, string) {
	g.t.Helper()
	id := uuid.New()
	roleID := "AROA" + strings.ToUpper(strings.ReplaceAll(id.String(), "-", ""))[:17]
	attrs := `{"path":"/"`
	if len(tags) > 0 {
		var parts []string
		for k, v := range tags {
			parts = append(parts, fmt.Sprintf("%q:%q", k, v))
		}
		attrs += `,"tags":{` + strings.Join(parts, ",") + `}`
	}
	attrs += `}`
	p3exec(g.t, g.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
		VALUES (?, ?, 'role', 'aws', ?, 'immutable', ?, ?, ?::jsonb)`,
		id, g.ws, "aws:iam:role:111111111111:"+name+":"+id.String()[:8], roleID, name, attrs)
	return id, roleID
}

// workload inserts a workload; consumes, when set, adds a live relationship
// of relType from it to that identity.
func (g *p3Gov) workload(name string, consumes *uuid.UUID, relType string) uuid.UUID {
	g.t.Helper()
	id := uuid.New()
	p3exec(g.t, g.db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key)
		VALUES (?, ?, 'ecs_task', ?, 'us-east-1', ?)`, id, g.ws, name, "aws\x1fp3own\x1f"+id.String())
	if consumes != nil {
		g.relate(id, *consumes, relType, "current")
	}
	return id
}

func (g *p3Gov) relate(workload, identity uuid.UUID, relType, state string) {
	g.t.Helper()
	validTo, reason := "NULL", ""
	if state == "ended" {
		validTo, reason = "now()", "not seen by an authoritative read"
	}
	p3exec(g.t, g.db, `INSERT INTO iga_relationship (workspace_id, relationship_type, source_workload_id, target_identity_account_id,
		basis, state, source_key, partition_key, connector_id, valid_to, ended_reason)
		VALUES (?, ?, ?, ?, 'declared', ?, ?, 'aws:111111111111', ?, `+validTo+`, ?)`,
		g.ws, relType, workload, identity, state, "rel:"+uuid.NewString(), g.conn, reason)
}

// lane creates one role under its own policy, ready for a deployment.
func (g *p3Gov) lane() p3Lane {
	g.t.Helper()
	g.lanes++
	l := p3Lane{policy: uuid.New(), version: uuid.New(), control: uuid.New(), target: uuid.New(), plan: uuid.New(), approval: uuid.New()}
	l.identity, l.roleID = g.identity(fmt.Sprintf("LaneRole%d", g.lanes), nil)
	arn := "arn:aws:iam::111111111111:role/LaneRole" + fmt.Sprint(g.lanes)
	boundary := "arn:aws:iam::111111111111:policy/authsec/AuthSecBoundary-" + l.roleID
	p3exec(g.t, g.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, ?, 'cloud_access', 'aws', ?)`,
		l.policy, g.ws, fmt.Sprintf("lane %d right-size", g.lanes), g.author)
	p3exec(g.t, g.db, `INSERT INTO iga_gov_policy_version (id, workspace_id, policy_id, version_no, intent, intent_hash, catalog_version, evidence_rev, created_by)
		VALUES (?, ?, ?, 1, '{"kind":"right_size_services"}', ?, 1, 1, ?)`, l.version, g.ws, l.policy, "ih-"+l.version.String(), g.author)
	p3exec(g.t, g.db, `INSERT INTO iga_gov_control (id, workspace_id, connector_id, account_id, role_id, role_arn, identity_account_id, policy_id, boundary_policy_arn)
		VALUES (?, ?, ?, '111111111111', ?, ?, ?, ?, ?)`, l.control, g.ws, g.conn, l.roleID, arn, l.identity, l.policy, boundary)
	p3exec(g.t, g.db, `INSERT INTO iga_gov_target (id, workspace_id, version_id, policy_id, control_id, is_canary) VALUES (?, ?, ?, ?, ?, true)`,
		l.target, g.ws, l.version, l.policy, l.control)
	p3exec(g.t, g.db, `INSERT INTO iga_gov_plan (id, workspace_id, version_id, target_id, control_id, kind, delivery, eligibility, basis, basis_read_at,
		  precondition, precondition_hash, desired_attachment, desired_boundary_arn, desired_document_hash, artifact_disposition,
		  evidence_bundle_id, evidence_rev, impact, impact_hash, operations, diff, plan_hash, material_hash)
		VALUES (?, ?, ?, ?, ?, 'apply', 'direct', 'eligible', 'live_read', now(),
		  '{"role_id":"AROA"}', ?, 'present', ?, ?, 'keep', ?, 1, '{}', ?, '[{"op":"CreatePolicy"},{"op":"PutRolePermissionsBoundary"}]', '{}', ?, ?)`,
		l.plan, g.ws, l.version, l.target, l.control, "ph-"+l.plan.String(), boundary, g.docHash, g.bundle,
		"imh-"+l.plan.String(), "plh-"+l.plan.String(), "mh-"+l.plan.String())
	p3exec(g.t, g.db, `INSERT INTO iga_gov_approval (id, workspace_id, version_id, decision, decided_by, channel, intent_hash, impact_hashes, plan_hashes, material_hashes, evidence_rev, expires_at)
		VALUES (?, ?, ?, 'approve', ?, 'ui', ?, ARRAY[?], ARRAY[?], ARRAY[?], 1, now() + interval '7 days')`,
		l.approval, g.ws, l.version, g.approver, "ih-"+l.version.String(), "imh-"+l.plan.String(), "plh-"+l.plan.String(), "mh-"+l.plan.String())
	return l
}

// deployment inserts a direct apply deployment of the lane in state.
func (g *p3Gov) deployment(l p3Lane, state string) uuid.UUID {
	g.t.Helper()
	id := uuid.New()
	p3exec(g.t, g.db, `INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		VALUES (?, ?, ?, ?, ?, ?, 'apply', 'direct', ?)`, id, g.ws, l.version, l.plan, l.control, l.approval, state)
	return id
}

// events returns the workspace's iga_gov_event names, oldest first.
func (g *p3Gov) events() []string {
	g.t.Helper()
	var out []string
	if err := g.db.Raw(`SELECT event FROM iga_gov_event WHERE workspace_id = ? ORDER BY id`, g.ws).Scan(&out).Error; err != nil {
		g.t.Fatal(err)
	}
	return out
}
