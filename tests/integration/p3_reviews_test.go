package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/notify"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// T3.12 (SPEC-iga-phase3-policy.md §7.4, §8.1 notify, §2.6, §2.8, §3.4,
// L-14; scenarios A5, A10, A23): the owner review service and the notify
// job against real PostgreSQL, with fake transports.
//
// Safeguards (mutation-checked): the gate's no-response blocker (silence is
// not consent); the age-confirmation check; reopen adding ONLY new owners;
// the notify job's dead-after-5 rule; the canary rule ignoring exceptions.

/* -------------------------------- fixture --------------------------------- */

type p3RevTarget struct {
	identity uuid.UUID
	roleID   string
	name     string
	removed  []string
	retained []string
	routes   []igagov.Route
}

type p3Rev struct {
	policy, version uuid.UUID
	targets         []uuid.UUID
	controls        []uuid.UUID
	plans           []uuid.UUID
	specs           []p3RevTarget
}

func p3Impact(t *testing.T, spec p3RevTarget, extraConsumers ...string) ([]byte, string) {
	t.Helper()
	im := igagov.Impact{Consumers: []igagov.ImpactConsumer{}, OwnerUserIDs: []string{}, Removed: []igagov.ImpactService{},
		Retained: []igagov.ImpactService{}, StatementRevisions: []string{}, Routes: append([]igagov.Route{}, spec.routes...)}
	for _, s := range spec.removed {
		im.Removed = append(im.Removed, igagov.ImpactService{Service: s, Basis: igagov.RemoveNoAttempt})
	}
	for _, s := range spec.retained {
		im.Retained = append(im.Retained, igagov.ImpactService{Service: s, Basis: igagov.RetainObserved})
	}
	for _, c := range extraConsumers {
		im.Consumers = append(im.Consumers, igagov.ImpactConsumer{WorkloadID: c, Relationship: models.RelTypeExecutesAs})
	}
	im = im.Normalized()
	h, err := igagov.ImpactHash(im)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(im)
	return raw, h
}

// reviewVersion creates a policy (or a new version of policy), a version
// whose intent removes `removals` (service -> grant_age_basis) and, per
// target role, a control, a target and a current apply plan with an impact.
func (g *p3Gov) reviewVersion(policy *uuid.UUID, versionNo int, removals map[string]string, specs ...p3RevTarget) p3Rev {
	g.t.Helper()
	r := p3Rev{version: uuid.New(), specs: specs}
	if policy == nil {
		r.policy = uuid.New()
		p3exec(g.t, g.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, ?, 'cloud_access', 'aws', ?)`,
			r.policy, g.ws, "review policy "+r.policy.String()[:8], g.author)
	} else {
		r.policy = *policy
	}
	var rm []map[string]any
	keys := make([]string, 0, len(removals))
	for k := range removals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, s := range keys {
		rm = append(rm, map[string]any{"service": s, "basis": "no_attempt", "qualified_days": 112, "grant_age_basis": removals[s]})
	}
	intent, _ := json.Marshal(map[string]any{"kind": "right_size_services", "remove": rm, "retain": []any{}, "subjects": []any{}})
	p3exec(g.t, g.db, `INSERT INTO iga_gov_policy_version (id, workspace_id, policy_id, version_no, intent, intent_hash, catalog_version, evidence_rev, created_by, status)
		VALUES (?, ?, ?, ?, ?::jsonb, ?, 1, 1, ?, 'in_review')`, r.version, g.ws, r.policy, versionNo, string(intent), "ih-"+r.version.String(), g.author)
	for i, s := range specs {
		control, target := uuid.New(), uuid.New()
		var existing []uuid.UUID
		g.db.Raw(`SELECT id FROM iga_gov_control WHERE workspace_id = ? AND identity_account_id = ? AND policy_id = ? AND state <> 'removed'`,
			g.ws, s.identity, r.policy).Scan(&existing)
		if len(existing) == 1 {
			control = existing[0]
		} else {
			p3exec(g.t, g.db, `INSERT INTO iga_gov_control (id, workspace_id, connector_id, account_id, role_id, role_arn, identity_account_id, policy_id, boundary_policy_arn)
				VALUES (?, ?, ?, '111111111111', ?, ?, ?, ?, ?)`, control, g.ws, g.conn, s.roleID, "arn:aws:iam::111111111111:role/"+s.name,
				s.identity, r.policy, "arn:aws:iam::111111111111:policy/authsec/AuthSecBoundary-"+s.roleID)
		}
		p3exec(g.t, g.db, `INSERT INTO iga_gov_target (id, workspace_id, version_id, policy_id, control_id, is_canary) VALUES (?, ?, ?, ?, ?, ?)`,
			target, g.ws, r.version, r.policy, control, i == 0)
		r.targets = append(r.targets, target)
		r.controls = append(r.controls, control)
		r.plans = append(r.plans, g.revPlan(r, i))
	}
	return r
}

// revPlan inserts the current apply plan of target i, with extra consumers
// in its impact (a different impact_hash).
func (g *p3Gov) revPlan(r p3Rev, i int, extraConsumers ...string) uuid.UUID {
	g.t.Helper()
	id := uuid.New()
	impact, hash := p3Impact(g.t, r.specs[i], extraConsumers...)
	boundary := "arn:aws:iam::111111111111:policy/authsec/AuthSecBoundary-" + r.specs[i].roleID
	p3exec(g.t, g.db, `INSERT INTO iga_gov_plan (id, workspace_id, version_id, target_id, control_id, kind, delivery, eligibility, basis, basis_read_at,
		  precondition, precondition_hash, desired_attachment, desired_boundary_arn, desired_document_hash, artifact_disposition,
		  evidence_bundle_id, evidence_rev, impact, impact_hash, operations, diff, plan_hash, material_hash)
		VALUES (?, ?, ?, ?, ?, 'apply', 'export', 'eligible', 'live_read', now(),
		  '{"role_id":"AROA"}', ?, 'present', ?, ?, 'keep', ?, 1, ?::jsonb, ?, '[]', '{}', ?, ?)`,
		id, g.ws, r.version, r.targets[i], r.controls[i], "ph-"+id.String(), boundary, g.docHash, g.bundle,
		string(impact), hash, "plh-"+id.String(), "mh-"+id.String())
	return id
}

// replan supersedes target i's plan with one whose impact names extra
// consumers (a recompilation after a consumer appeared).
func (g *p3Gov) replan(r *p3Rev, i int, extraConsumers ...string) {
	g.t.Helper()
	p3exec(g.t, g.db, `UPDATE iga_gov_plan SET superseded_at = now() WHERE workspace_id = ? AND id = ?`, g.ws, r.plans[i])
	r.plans[i] = g.revPlan(*r, i, extraConsumers...)
}

/* ------------------------------- transports ------------------------------- */

type p3Outbox struct {
	mu   sync.Mutex
	sent []notify.Message
	fail error
}

func (o *p3Outbox) Send(_ context.Context, m notify.Message) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fail != nil {
		return o.fail
	}
	o.sent = append(o.sent, m)
	return nil
}

func (o *p3Outbox) setFail(err error) { o.mu.Lock(); o.fail = err; o.mu.Unlock() }

func (o *p3Outbox) to(addr string) []notify.Message {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []notify.Message
	for _, m := range o.sent {
		if m.To == addr {
			out = append(out, m)
		}
	}
	return out
}

// p3NotifyWorker is a policy worker with only the notify kind, over the
// given transports (the production JobKind: handler and backoff).
func p3NotifyWorker(db *gorm.DB, email, webhook notify.Sender) *services.PolicyJobWorker {
	w := services.NewPolicyJobWorker(db, "p3-notify-test-"+uuid.NewString()[:8]).WithGate(func() bool { return true })
	w.Register(services.NewGovNotifier(db).WithTransports(email, webhook).JobKind())
	return w
}

func p3Drain(t *testing.T, w *services.PolicyJobWorker) int {
	t.Helper()
	n := 0
	for i := 0; i < 100; i++ {
		ran, err := w.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !ran {
			return n
		}
		n++
	}
	t.Fatal("notify jobs did not drain")
	return n
}

/* --------------------------------- hooks ---------------------------------- */

type p3AuthoringHook struct {
	mu    sync.Mutex
	calls []services.GovOwnerResponseEvent
	newID uuid.UUID
}

func (h *p3AuthoringHook) OwnerResponseTx(tx *gorm.DB, r services.GovOwnerResponseEvent) (*uuid.UUID, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, r)
	if r.Response == services.GovResponseRetain {
		id := h.newID
		return &id, nil
	}
	return nil, nil
}

/* -------------------------------- helpers --------------------------------- */

func wantGov(t *testing.T, err error, code string) *services.GovError {
	t.Helper()
	var ge *services.GovError
	if code == "" {
		if err != nil {
			t.Fatalf("want nil, got %v", err)
		}
		return nil
	}
	if !errors.As(err, &ge) || ge.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	return ge
}

func blockerKinds(t *testing.T, ge *services.GovError) []string {
	t.Helper()
	bs, _ := ge.Detail["blockers"].([]services.GovReviewBlocker)
	var out []string
	for _, b := range bs {
		out = append(out, b.Kind)
	}
	sort.Strings(out)
	return out
}

func p3Ack(ages []string, routes ...[2]string) services.GovRespondInput {
	in := services.GovRespondInput{Response: services.GovResponseAcknowledge}
	for _, a := range ages {
		in.AgeConfirmations = append(in.AgeConfirmations, services.GovAgeConfirmation{Service: a, Confirmed: true})
	}
	for _, r := range routes {
		in.RouteConfirmations = append(in.RouteConfirmations, services.GovRouteConfirmation{Service: r[0], Route: r[1], Confirmed: true})
	}
	return in
}

func (g *p3Gov) reviewOf(version uuid.UUID) models.IGAGovOwnerReview {
	g.t.Helper()
	var rv models.IGAGovOwnerReview
	if err := g.db.Where("workspace_id = ? AND version_id = ?", g.ws, version).Take(&rv).Error; err != nil {
		g.t.Fatal(err)
	}
	return rv
}

func (g *p3Gov) eventsNamed(prefix string) []models.IGAGovEvent {
	g.t.Helper()
	var out []models.IGAGovEvent
	if err := g.db.Where("workspace_id = ? AND event LIKE ?", g.ws, prefix+"%").Order("id").Find(&out).Error; err != nil {
		g.t.Fatal(err)
	}
	return out
}

/* --------------------------------- tests ---------------------------------- */

// A5 (L-14 owner gate): no response blocks; a missing owner blocks; both
// until an approver's exception (never the author's); retain dynamodb calls
// the authoring hook (new version) and blocks this version; an
// acknowledgement without the age confirmation is 409 age_unconfirmed, and
// without the route confirmation 409 route_unconfirmed.
func TestP3T312A5OwnerGate(t *testing.T) {
	db := igaDB(t)
	g := p3NewGov(t, db, "p3notify-a5")
	hook := &p3AuthoringHook{newID: uuid.New()}
	svc := services.NewIGAGovOwnerReviewService(db).WithAuthoringHook(hook)
	ctx := context.Background()

	refund, refundRoleID := g.identity("RefundTaskRole", nil)
	orphan, orphanRoleID := g.identity("OrphanRole", nil)
	wl := g.workload("refund-agent", &refund, models.RelTypeExecutesAs)
	u1, _ := g.member("u1-a5@p3notify.test", "Una Owner", "active")
	p3Manual(t, db, g, models.GovObjectWorkload, wl, u1, models.GovOwnerAccountable)

	removals := map[string]string{"sqs": igagov.GrantAgePredatesObservation, "dynamodb": igagov.GrantAgeObservedSinceChange}
	t.Run("missing owner and no response block until an exception", func(t *testing.T) {
		rev := g.reviewVersion(nil, 1, removals,
			p3RevTarget{identity: refund, roleID: refundRoleID, name: "RefundTaskRole", removed: []string{"sqs", "dynamodb"}, retained: []string{"s3"}},
			p3RevTarget{identity: orphan, roleID: orphanRoleID, name: "OrphanRole", removed: []string{"sqs"}})
		// No review yet: incomplete.
		ge := wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
		if ge.Detail["reason"] != "no_review" {
			t.Fatalf("no review: %v", ge.Detail)
		}
		sync, err := svc.OpenReview(ctx, g.ws, rev.version, g.author)
		if err != nil || !sync.Created || len(sync.NewOwners) != 1 || sync.NewOwners[0] != u1 || sync.Status != services.GovReviewOpen {
			t.Fatalf("open: %+v %v", sync, err)
		}
		// One email notice to u1, and its job.
		var notes []models.IGAGovNotification
		db.Where("workspace_id = ? AND subject_id = ?", g.ws, sync.ReviewID).Find(&notes)
		if len(notes) != 1 || notes[0].Channel != "email" || notes[0].Recipient != "user:"+u1.String() || notes[0].State != "pending" {
			t.Fatalf("notices: %+v", notes)
		}
		var jobs int64
		db.Raw(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'notify' AND dedupe_key = ?`, g.ws, "notification:"+notes[0].ID.String()).Scan(&jobs)
		if jobs != 1 {
			t.Fatalf("notify jobs: %d", jobs)
		}
		ge = wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
		if got := strings.Join(blockerKinds(t, ge), ","); got != "missing_owner,no_response" {
			t.Fatalf("blockers %s", got)
		}
		// u1 acknowledges with every confirmation: the missing owner still blocks.
		if _, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, p3Ack([]string{"sqs"})); err != nil {
			t.Fatal(err)
		}
		ge = wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
		if got := strings.Join(blockerKinds(t, ge), ","); got != "missing_owner" {
			t.Fatalf("blockers after ack %s", got)
		}
		if g.reviewOf(rev.version).Status != services.GovReviewOpen {
			t.Fatal("a review with a missing owner completed")
		}
		// The author may not except; a non-owner may not respond.
		_, _, err = svc.Except(ctx, g.ws, g.author, sync.ReviewID, "ship it")
		wantGov(t, err, "self_approval")
		if _, err := svc.Respond(ctx, g.ws, g.approver, sync.ReviewID, p3Ack(nil)); !errors.Is(err, services.ErrNotReviewOwner) {
			t.Fatalf("non-owner respond: %v", err)
		}
		_, _, err = svc.Except(ctx, g.ws, g.approver, sync.ReviewID, " ")
		wantGov(t, err, "invalid_parameter")
		_, after, err := svc.Except(ctx, g.ws, g.approver, sync.ReviewID, "OrphanRole is a lab role; owner assigned next week")
		if err != nil || after.Status != services.GovReviewExcepted {
			t.Fatalf("except: %+v %v", after, err)
		}
		wantGov(t, svc.CheckGate(db, g.ws, rev.version), "")
		// Closed: no more responses.
		_, err = svc.Respond(ctx, g.ws, u1, sync.ReviewID, p3Ack(nil))
		wantGov(t, err, "review_closed")
	})

	t.Run("retain calls the authoring hook and blocks; age and route confirmations", func(t *testing.T) {
		route := igagov.Route{Service: "sqs", Resource: "arn:aws:sqs:us-east-1:111111111111:refunds", Principal: igagov.PrincipalRoleSession,
			Effect: igagov.RouteEffectBypassKnown}
		refund2, rid2 := g.identity("RefundTaskRole2", nil)
		wl2 := g.workload("refund-agent-2", &refund2, models.RelTypeExecutesAs)
		p3Manual(t, db, g, models.GovObjectWorkload, wl2, u1, models.GovOwnerAccountable)
		rev := g.reviewVersion(nil, 1, removals,
			p3RevTarget{identity: refund2, roleID: rid2, name: "RefundTaskRole2", removed: []string{"sqs", "dynamodb"}, routes: []igagov.Route{route}})
		sync, err := svc.OpenReview(ctx, g.ws, rev.version, g.author)
		if err != nil {
			t.Fatal(err)
		}
		// Validation: retain needs items with a reason and a future date, of
		// a removed service; object needs a comment; unrequested confirmations
		// are refused.
		for name, in := range map[string]services.GovRespondInput{
			"retain without items": {Response: "retain"},
			"retain kept service":  {Response: "retain", RetainItems: []services.GovRetainItem{{Service: "s3", Reason: "x", ReviewBy: "2099-01-01"}}},
			"retain no reason":     {Response: "retain", RetainItems: []services.GovRetainItem{{Service: "dynamodb", ReviewBy: "2099-01-01"}}},
			"retain past date":     {Response: "retain", RetainItems: []services.GovRetainItem{{Service: "dynamodb", Reason: "x", ReviewBy: "2001-01-01"}}},
			"object no comment":    {Response: "object"},
			"bad response":         {Response: "maybe"},
			"unrequested age":      {Response: "acknowledge", AgeConfirmations: []services.GovAgeConfirmation{{Service: "dynamodb", Confirmed: true}}},
			"unconfirmed age":      {Response: "acknowledge", AgeConfirmations: []services.GovAgeConfirmation{{Service: "sqs", Confirmed: false}}},
			"unrequested route":    {Response: "acknowledge", RouteConfirmations: []services.GovRouteConfirmation{{Service: "sqs", Route: "arn:other", Confirmed: true}}},
		} {
			_, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, in)
			if ge := wantGov(t, err, "invalid_parameter"); ge == nil {
				t.Fatalf("%s accepted", name)
			}
		}
		// Retain dynamodb: the hook creates the new version; this one is blocked.
		res, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, services.GovRespondInput{Response: "retain",
			RetainItems: []services.GovRetainItem{{Service: "dynamodb", Reason: "quarterly reconciliation job", ReviewBy: "2099-01-15"}}})
		if err != nil || res.NewVersionID == nil || *res.NewVersionID != hook.newID {
			t.Fatalf("retain: %+v %v", res, err)
		}
		if len(hook.calls) != 1 || hook.calls[0].VersionID != rev.version || hook.calls[0].UserID != u1 ||
			len(hook.calls[0].RetainItems) != 1 || hook.calls[0].RetainItems[0].Service != "dynamodb" {
			t.Fatalf("hook calls %+v", hook.calls)
		}
		ge := wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
		if got := strings.Join(blockerKinds(t, ge), ","); got != "retained" {
			t.Fatalf("blockers after retain: %s", got)
		}
		evs := g.eventsNamed("review.responded")
		var p map[string]any
		_ = json.Unmarshal(evs[len(evs)-1].Payload, &p)
		if p["new_version_id"] != hook.newID.String() || evs[len(evs)-1].VersionID == nil || *evs[len(evs)-1].VersionID != rev.version {
			t.Fatalf("responded event %s %+v", evs[len(evs)-1].Payload, evs[len(evs)-1])
		}
		// Object: comment required, hook told, blocks.
		if _, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, services.GovRespondInput{Response: "object", Comment: "the nightly export uses sqs"}); err != nil {
			t.Fatal(err)
		}
		ge = wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
		if got := strings.Join(blockerKinds(t, ge), ","); got != "objection" || len(hook.calls) != 2 || hook.calls[1].Response != "object" {
			t.Fatalf("after object: %s %+v", got, hook.calls)
		}
		// Acknowledge without confirmations: complete, but age_unconfirmed.
		res, err = svc.Respond(ctx, g.ws, u1, sync.ReviewID, p3Ack(nil))
		if err != nil || res.ReviewStatus != services.GovReviewComplete {
			t.Fatalf("ack: %+v %v", res, err)
		}
		ge = wantGov(t, svc.CheckGate(db, g.ws, rev.version), "age_unconfirmed")
		items, _ := ge.Detail["items"].([]services.GovAgeItem)
		if len(items) != 1 || items[0].Service != "sqs" || items[0].GrantAgeBasis != igagov.GrantAgePredatesObservation {
			t.Fatalf("age items %+v", items)
		}
		// Age confirmed, route not: route_unconfirmed.
		if _, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, p3Ack([]string{"sqs"})); err != nil {
			t.Fatal(err)
		}
		ge = wantGov(t, svc.CheckGate(db, g.ws, rev.version), "route_unconfirmed")
		ritems, _ := ge.Detail["items"].([]services.GovRouteItem)
		if len(ritems) != 1 || ritems[0].Route != route.Resource || ritems[0].Effect != igagov.RouteEffectBypassKnown {
			t.Fatalf("route items %+v", ritems)
		}
		if _, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, p3Ack([]string{"sqs"}, [2]string{"sqs", route.Resource})); err != nil {
			t.Fatal(err)
		}
		wantGov(t, svc.CheckGate(db, g.ws, rev.version), "")
		// An objection after completion reopens the gate (status back to open).
		if res, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, services.GovRespondInput{Response: "object", Comment: "changed my mind"}); err != nil || res.ReviewStatus != services.GovReviewOpen {
			t.Fatalf("object after complete: %+v %v", res, err)
		}
		wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
	})

	t.Run("cross-workspace review ids are not found", func(t *testing.T) {
		other := p3NewGov(t, db, "p3notify-a5-other")
		rv := g.eventsNamed("review.opened")
		var p map[string]any
		_ = json.Unmarshal(rv[0].Payload, &p)
		rid := uuid.MustParse(p["review_id"].(string))
		_, err := svc.Respond(ctx, other.ws, other.author, rid, p3Ack(nil))
		wantGov(t, err, "not_found")
		_, _, err = svc.Except(ctx, other.ws, other.approver, rid, "x")
		wantGov(t, err, "not_found")
		_, err = svc.Remind(ctx, other.ws, other.author, rid)
		wantGov(t, err, "not_found")
		_, err = svc.View(ctx, other.ws, rid, uuid.Nil)
		wantGov(t, err, "not_found")
		wantGov(t, svc.CheckGate(db, other.ws, *rv[0].VersionID), "not_found")
	})
}

// A10 (shared role): both consumers' owners are asked and emailed; the
// canary may be the shared role only when both acknowledged -- an exception
// does not count.
func TestP3T312A10SharedRole(t *testing.T) {
	db := igaDB(t)
	ctx := context.Background()
	mail := &p3Outbox{}
	w := p3NotifyWorker(db, mail, &p3Outbox{})

	setup := func(name string) (*p3Gov, p3Rev, uuid.UUID, uuid.UUID, uuid.UUID) {
		g := p3NewGov(t, db, name)
		role, rid := g.identity("SharedRole", nil)
		w1 := g.workload("refund-agent", &role, models.RelTypeExecutesAs)
		w2 := g.workload("refund-reconciler", &role, models.RelTypeExecutesAs)
		u1, _ := g.member("akash-"+g.ws.String()[:6]+"@p3notify.test", "Akash M.", "active")
		u2, _ := g.member("priya-"+g.ws.String()[:6]+"@p3notify.test", "Priya K.", "active")
		p3Manual(t, db, g, models.GovObjectWorkload, w1, u1, models.GovOwnerAccountable)
		p3Manual(t, db, g, models.GovObjectWorkload, w2, u2, models.GovOwnerAccountable)
		rev := g.reviewVersion(nil, 1, map[string]string{"ec2": igagov.GrantAgeObservedSinceChange},
			p3RevTarget{identity: role, roleID: rid, name: "SharedRole", removed: []string{"ec2"}, retained: []string{"s3"}})
		return g, rev, u1, u2, role
	}
	svc := services.NewIGAGovOwnerReviewService(db)

	g, rev, u1, u2, _ := setup("p3notify-a10")
	sync, err := svc.OpenReview(ctx, g.ws, rev.version, g.author)
	if err != nil || len(sync.NewOwners) != 2 {
		t.Fatalf("open: %+v %v", sync, err)
	}
	p3Drain(t, w)
	for _, u := range []struct {
		id   uuid.UUID
		addr string
	}{{u1, "akash-" + g.ws.String()[:6] + "@p3notify.test"}, {u2, "priya-" + g.ws.String()[:6] + "@p3notify.test"}} {
		got := mail.to(u.addr)
		if len(got) != 1 || !strings.Contains(got[0].Subject, "SharedRole") || !strings.Contains(string(got[0].Body), "please review") && !strings.Contains(string(got[0].Body), "Please review") {
			t.Fatalf("mail to %s: %+v", u.addr, got)
		}
		var r models.IGAGovOwnerResponse
		db.Where("review_id = ? AND user_id = ?", sync.ReviewID, u.id).Take(&r)
		if r.Delivery != "delivered" || strings.Join(r.DeliveryChannels, ",") != "email" {
			t.Fatalf("delivery for %s: %s %v", u.addr, r.Delivery, r.DeliveryChannels)
		}
	}
	// Each email names the workload its owner owns.
	if b := string(mail.to("akash-" + g.ws.String()[:6] + "@p3notify.test")[0].Body); !strings.Contains(b, "refund-agent (accountable workload)") {
		t.Fatalf("akash's mail does not name refund-agent:\n%s", b)
	}
	ack, err := svc.CanaryAcknowledgement(db, g.ws, rev.version, rev.targets[0])
	if err != nil || !ack.Shared || ack.Acknowledged || len(ack.Missing) != 2 {
		t.Fatalf("canary before acks: %+v %v", ack, err)
	}
	if _, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, p3Ack(nil)); err != nil {
		t.Fatal(err)
	}
	ack, _ = svc.CanaryAcknowledgement(db, g.ws, rev.version, rev.targets[0])
	if ack.Acknowledged || len(ack.Missing) != 1 || ack.Missing[0] != u2 {
		t.Fatalf("canary after one ack: %+v", ack)
	}
	// An exception lets the version proceed but is not an acknowledgement.
	if _, _, err := svc.Except(ctx, g.ws, g.approver, sync.ReviewID, "priya is on leave"); err != nil {
		t.Fatal(err)
	}
	wantGov(t, svc.CheckGate(db, g.ws, rev.version), "")
	ack, _ = svc.CanaryAcknowledgement(db, g.ws, rev.version, rev.targets[0])
	if ack.Acknowledged {
		t.Fatal("an exception counted as the second owner's acknowledgement")
	}

	// Both acknowledge: the shared role may be the canary; the review completes.
	g2, rev2, v1, v2, _ := setup("p3notify-a10-both")
	s2, err := svc.OpenReview(ctx, g2.ws, rev2.version, g2.author)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []uuid.UUID{v1, v2} {
		if _, err := svc.Respond(ctx, g2.ws, u, s2.ReviewID, p3Ack(nil)); err != nil {
			t.Fatal(err)
		}
	}
	ack, _ = svc.CanaryAcknowledgement(db, g2.ws, rev2.version, rev2.targets[0])
	if !ack.Shared || !ack.Acknowledged || g2.reviewOf(rev2.version).Status != services.GovReviewComplete {
		t.Fatalf("both acks: %+v status %s", ack, g2.reviewOf(rev2.version).Status)
	}
	wantGov(t, svc.CheckGate(db, g2.ws, rev2.version), "")
	if n := len(g2.eventsNamed("review.completed")); n != 1 {
		t.Fatalf("review.completed events: %d", n)
	}
}

// A23 (impact change): after the review completed, a new workload starts
// running as the role; the recompiled plan's impact_hash differs. The gate
// refuses at once (impact_changed); the resync reopens the review for the
// NEW owner only -- earlier acknowledgements stand, nobody else is
// re-notified -- and the gate holds until the new owner answers.
func TestP3T312A23ReopenOnImpactChange(t *testing.T) {
	db := igaDB(t)
	ctx := context.Background()
	g := p3NewGov(t, db, "p3notify-a23")
	svc := services.NewIGAGovOwnerReviewService(db)
	mail := &p3Outbox{}
	w := p3NotifyWorker(db, mail, &p3Outbox{})

	role, rid := g.identity("RefundTaskRole", nil)
	w1 := g.workload("refund-agent", &role, models.RelTypeExecutesAs)
	u1, _ := g.member("u1-a23@p3notify.test", "Una One", "active")
	u3, _ := g.member("u3-a23@p3notify.test", "Tia Three", "active")
	p3Manual(t, db, g, models.GovObjectWorkload, w1, u1, models.GovOwnerAccountable)
	rev := g.reviewVersion(nil, 1, map[string]string{"ec2": igagov.GrantAgeObservedSinceChange},
		p3RevTarget{identity: role, roleID: rid, name: "RefundTaskRole", removed: []string{"ec2"}})
	sync, err := svc.OpenReview(ctx, g.ws, rev.version, g.author)
	if err != nil {
		t.Fatal(err)
	}
	p3Drain(t, w)
	if _, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, p3Ack(nil)); err != nil {
		t.Fatal(err)
	}
	wantGov(t, svc.CheckGate(db, g.ws, rev.version), "")
	before := g.reviewOf(rev.version)
	var u1Note models.IGAGovNotification
	db.Where("subject_id = ? AND recipient = ?", sync.ReviewID, "user:"+u1.String()).Take(&u1Note)

	// A new workload runs as the role, owned by u3; the plan is recompiled.
	w3 := g.workload("refund-batch", &role, models.RelTypeExecutesAs)
	p3Manual(t, db, g, models.GovObjectWorkload, w3, u3, models.GovOwnerAccountable)
	g.replan(&rev, 0, w3.String())
	ge := wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
	if ge.Detail["reason"] != "impact_changed" {
		t.Fatalf("before resync: %v", ge.Detail)
	}
	re, err := svc.OpenReview(ctx, g.ws, rev.version, uuid.Nil)
	if err != nil || !re.Reopened || re.Created || len(re.NewOwners) != 1 || re.NewOwners[0] != u3 || re.Status != services.GovReviewReopened {
		t.Fatalf("resync: %+v %v", re, err)
	}
	after := g.reviewOf(rev.version)
	if after.ID != before.ID || sameSlice(after.ImpactHashes, before.ImpactHashes) || !after.DeadlineAt.After(before.DeadlineAt.Add(-time.Second)) {
		t.Fatalf("reopened review %+v (before %+v)", after, before)
	}
	var r1 models.IGAGovOwnerResponse
	db.Where("review_id = ? AND user_id = ?", sync.ReviewID, u1).Take(&r1)
	if r1.Response == nil || *r1.Response != "acknowledge" {
		t.Fatal("the reopen discarded the earlier acknowledgement")
	}
	var u1After models.IGAGovNotification
	db.Where("id = ?", u1Note.ID).Take(&u1After)
	if u1After.State != "sent" || u1After.AttemptCount != u1Note.AttemptCount {
		t.Fatalf("the existing owner was re-notified: %+v", u1After)
	}
	var notes int64
	db.Raw(`SELECT count(*) FROM iga_gov_notification WHERE subject_id = ? AND recipient = ?`, sync.ReviewID, "user:"+u3.String()).Scan(&notes)
	if notes != 1 {
		t.Fatalf("notices to the new owner: %d", notes)
	}
	p3Drain(t, w)
	if len(mail.to("u1-a23@p3notify.test")) != 1 || len(mail.to("u3-a23@p3notify.test")) != 1 {
		t.Fatalf("mail: u1 %d, u3 %d", len(mail.to("u1-a23@p3notify.test")), len(mail.to("u3-a23@p3notify.test")))
	}
	ev := g.eventsNamed("review.reopened")
	var p map[string]any
	_ = json.Unmarshal(ev[0].Payload, &p)
	if len(ev) != 1 || p["reason"] != "impact_changed" || fmt.Sprint(p["new_owner_user_ids"]) != "["+u3.String()+"]" {
		t.Fatalf("reopened event %s", ev[0].Payload)
	}
	ge = wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
	if got := strings.Join(blockerKinds(t, ge), ","); got != "no_response" {
		t.Fatalf("after reopen: %s", got)
	}
	// A resync with nothing new changes nothing.
	if again, err := svc.OpenReview(ctx, g.ws, rev.version, uuid.Nil); err != nil || again.Reopened || len(again.NewOwners) != 0 {
		t.Fatalf("idempotent resync: %+v %v", again, err)
	}
	if _, err := svc.Respond(ctx, g.ws, u3, sync.ReviewID, p3Ack(nil)); err != nil {
		t.Fatal(err)
	}
	wantGov(t, svc.CheckGate(db, g.ws, rev.version), "")
	if g.reviewOf(rev.version).Status != services.GovReviewComplete {
		t.Fatal("not complete after the new owner acknowledged")
	}
}

func sameSlice(a, b []string) bool {
	return strings.Join(a, ",") == strings.Join(b, ",")
}

// The notify job (§8.1): a failing delivery is retried attempt x 10 min and
// dead after 5; the owner's delivery then reads failed and blocks the
// review (L-14 "delivery failure blocks"); a reminder starts a new cycle
// that delivers. Every outcome is an event.
func TestP3T312NotifyRetryAndDead(t *testing.T) {
	db := igaDB(t)
	ctx := context.Background()
	g := p3NewGov(t, db, "p3notify-retry")
	svc := services.NewIGAGovOwnerReviewService(db)
	mail := &p3Outbox{}
	mail.setFail(errors.New("relay refused: 451 try again"))
	w := p3NotifyWorker(db, mail, &p3Outbox{})

	role, rid := g.identity("RetryRole", nil)
	wl := g.workload("retry-agent", &role, models.RelTypeExecutesAs)
	u1, _ := g.member("u1-retry@p3notify.test", "Una One", "active")
	p3Manual(t, db, g, models.GovObjectWorkload, wl, u1, models.GovOwnerAccountable)
	rev := g.reviewVersion(nil, 1, map[string]string{"ec2": igagov.GrantAgeObservedSinceChange},
		p3RevTarget{identity: role, roleID: rid, name: "RetryRole", removed: []string{"ec2"}})
	sync, err := svc.OpenReview(ctx, g.ws, rev.version, g.author)
	if err != nil {
		t.Fatal(err)
	}
	var n models.IGAGovNotification
	db.Where("workspace_id = ? AND subject_id = ?", g.ws, sync.ReviewID).Take(&n)
	job := func() models.IGAGovJob {
		var j models.IGAGovJob
		db.Where("workspace_id = ? AND kind = 'notify' AND subject_id = ?", g.ws, n.ID).Order("created_at DESC").Take(&j)
		return j
	}
	for attempt := 1; attempt <= 5; attempt++ {
		before := time.Now()
		if ran, err := w.RunOnce(ctx); err != nil || !ran {
			t.Fatalf("attempt %d: ran %v %v", attempt, ran, err)
		}
		var cur models.IGAGovNotification
		db.Where("id = ?", n.ID).Take(&cur)
		j := job()
		if cur.AttemptCount != attempt || !strings.Contains(cur.LastError, "451") {
			t.Fatalf("attempt %d: %+v", attempt, cur)
		}
		if attempt < 5 {
			wantDelay := time.Duration(attempt) * 10 * time.Minute
			if cur.State != "failed" || cur.AvailableAt.Before(before.Add(wantDelay-time.Minute)) || cur.AvailableAt.After(time.Now().Add(wantDelay+time.Minute)) {
				t.Fatalf("attempt %d: state %s available_at %v (want ~+%s)", attempt, cur.State, cur.AvailableAt, wantDelay)
			}
			if j.Status != "queued" || j.Attempts != attempt || j.RunAfter.Before(before.Add(wantDelay-time.Minute)) {
				t.Fatalf("attempt %d: job %s attempts %d run_after %v", attempt, j.Status, j.Attempts, j.RunAfter)
			}
			// Nothing is claimable before the backoff; then make it due.
			if ran, _ := w.RunOnce(ctx); ran {
				t.Fatalf("attempt %d: the job ran again before its backoff", attempt)
			}
			p3exec(t, db, `UPDATE iga_gov_job SET run_after = ? WHERE id = ?`, time.Now().Add(-time.Second), j.ID) // the worker's clock (T3.08)
		} else {
			if cur.State != "dead" || j.Status != "failed" || j.Attempts != 5 {
				t.Fatalf("after 5: notification %s, job %s/%d", cur.State, j.Status, j.Attempts)
			}
		}
	}
	var names []string
	for _, e := range g.eventsNamed("notification.") {
		names = append(names, e.Event)
	}
	if strings.Join(names, ",") != "notification.failed,notification.failed,notification.failed,notification.failed,notification.dead" {
		t.Fatalf("notification events %v", names)
	}
	var r models.IGAGovOwnerResponse
	db.Where("review_id = ? AND user_id = ?", sync.ReviewID, u1).Take(&r)
	if r.Delivery != "failed" {
		t.Fatalf("delivery after dead: %s", r.Delivery)
	}
	ge := wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
	if got := strings.Join(blockerKinds(t, ge), ","); got != "delivery_failed" {
		t.Fatalf("blockers %s", got)
	}
	// Remind: a new cycle (pending, attempt 0, a new job) that delivers.
	mail.setFail(nil)
	reminded, err := svc.Remind(ctx, g.ws, g.author, sync.ReviewID)
	if err != nil || len(reminded) != 1 || reminded[0] != u1 {
		t.Fatalf("remind: %v %v", reminded, err)
	}
	var cur models.IGAGovNotification
	db.Where("id = ?", n.ID).Take(&cur)
	if cur.State != "pending" || cur.AttemptCount != 0 {
		t.Fatalf("after remind: %+v", cur)
	}
	p3Drain(t, w)
	db.Where("id = ?", n.ID).Take(&cur)
	db.Where("review_id = ? AND user_id = ?", sync.ReviewID, u1).Take(&r)
	if cur.State != "sent" || cur.SentAt == nil || r.Delivery != "delivered" || len(mail.to("u1-retry@p3notify.test")) != 1 {
		t.Fatalf("after reminder delivery: %+v delivery %s", cur, r.Delivery)
	}
	ge = wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
	if got := strings.Join(blockerKinds(t, ge), ","); got != "no_response" {
		t.Fatalf("blockers after delivery %s", got)
	}
	// A recipient who left the workspace is dead at once (permanent).
	p3exec(t, db, `UPDATE workspace_memberships SET status = 'suspended' WHERE user_id = ?`, u1)
	if _, err := svc.Remind(ctx, g.ws, g.author, sync.ReviewID); err != nil {
		t.Fatal(err)
	}
	// u1 is no longer an active member: not an owner who can be asked, so
	// nobody is reminded and no notice is reset.
	db.Where("id = ?", n.ID).Take(&cur)
	if cur.State != "sent" {
		t.Fatalf("a suspended owner was reminded: %+v", cur)
	}
	ge = wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
	if got := strings.Join(blockerKinds(t, ge), ","); got != "missing_owner,owner_not_member" {
		t.Fatalf("blockers with a suspended owner: %s", got)
	}
}

// The production worker registers notify with §8.1's backoff.
func TestP3T312DefaultWorkerHasNotify(t *testing.T) {
	db := igaDB(t)
	w := services.NewDefaultPolicyJobWorker(db)
	found := false
	for _, k := range w.Kinds() {
		if k == repositories.GovJobNotify {
			found = true
		}
	}
	if !found {
		t.Fatalf("notify not registered: %v", w.Kinds())
	}
	if services.GovNotifyBackoff(1) != 10*time.Minute || services.GovNotifyBackoff(4) != 40*time.Minute || services.GovNotifyMaxAttempts != 5 {
		t.Fatal("notify backoff is not attempt x 10 min, dead after 5")
	}
}

// A reminder while a notice waits in its backoff starts the new cycle at
// once with its own 5 attempts (the queued job is made due, attempts 0).
func TestP3T312RemindDuringBackoff(t *testing.T) {
	db := igaDB(t)
	ctx := context.Background()
	g := p3NewGov(t, db, "p3notify-remind-backoff")
	svc := services.NewIGAGovOwnerReviewService(db)
	mail := &p3Outbox{}
	mail.setFail(errors.New("relay down"))
	w := p3NotifyWorker(db, mail, &p3Outbox{})
	role, rid := g.identity("BackoffRole", nil)
	wl := g.workload("backoff-agent", &role, models.RelTypeExecutesAs)
	u1, _ := g.member("u1-backoff@p3notify.test", "Una One", "active")
	p3Manual(t, db, g, models.GovObjectWorkload, wl, u1, models.GovOwnerAccountable)
	rev := g.reviewVersion(nil, 1, map[string]string{"ec2": igagov.GrantAgeObservedSinceChange},
		p3RevTarget{identity: role, roleID: rid, name: "BackoffRole", removed: []string{"ec2"}})
	sync, err := svc.OpenReview(ctx, g.ws, rev.version, g.author)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if ran, err := w.RunOnce(ctx); err != nil || !ran {
			t.Fatalf("try %d: %v %v", i, ran, err)
		}
		p3exec(t, db, `UPDATE iga_gov_job SET run_after = ? WHERE workspace_id = ? AND kind = 'notify' AND status = 'queued'`, time.Now().Add(-time.Second), g.ws)
	}
	p3exec(t, db, `UPDATE iga_gov_job SET run_after = ? WHERE workspace_id = ? AND kind = 'notify' AND status = 'queued'`, time.Now().Add(30*time.Minute), g.ws)
	mail.setFail(nil)
	if _, err := svc.Remind(ctx, g.ws, g.author, sync.ReviewID); err != nil {
		t.Fatal(err)
	}
	var j models.IGAGovJob
	db.Where("workspace_id = ? AND kind = 'notify'", g.ws).Take(&j)
	if j.Status != "queued" || j.Attempts != 0 || j.RunAfter.After(time.Now().Add(time.Second)) {
		t.Fatalf("job after the reminder: %s attempts %d run_after %v", j.Status, j.Attempts, j.RunAfter)
	}
	p3Drain(t, w)
	if len(mail.to("u1-backoff@p3notify.test")) != 1 {
		t.Fatal("the reminder was not delivered at once")
	}
}
