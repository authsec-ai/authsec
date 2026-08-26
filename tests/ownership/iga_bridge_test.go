// The bridge between the k8s runtime inventory and the correlated IGA estate.
//
// Two agent models coexist in this service, built independently: discovered_agents
// (what is running in a cluster right now, keyed by fingerprint) and iga_agents
// (the logical agent across every channel, correlated and classified). Neither
// subsumes the other, so what was missing was the join.
//
// The property these tests defend: the join may only ever be PROPOSED. The two
// models share no identifier -- iga_agents has no fingerprint, iga_identity_accounts
// has no client reference, native keys live in iga_source_objects behind
// iga_correlations -- so the only field both sides carry is a display name, which is
// weak evidence. Auto-accepting a name match would invent a correlation.
package ownership

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// igaFixture builds a provisioning fixture plus a canonical agent in the estate.
type igaFixture struct {
	provFixture
	bm       services.IGABridgeManager
	igaAgent uuid.UUID
}

func newIGAFixture(t *testing.T, canonicalName string) igaFixture {
	t.Helper()
	f := newProvFixture(t)
	id := uuid.New()
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name)
	                VALUES ($1, $2, $3)`, id, f.ws, canonicalName)
	return igaFixture{provFixture: f, bm: services.NewIGABridgeManager(gormFor(t, f.raw)), igaAgent: id}
}

// agentName reads the fixture agent's display name, so the tests correlate against
// whatever the shared fixture actually created rather than a guess.
func agentName(t *testing.T, f provFixture) string {
	t.Helper()
	var name string
	if err := f.raw.QueryRow(`SELECT display_name FROM discovered_agents WHERE id = $1`,
		f.agent).Scan(&name); err != nil {
		t.Fatalf("read display name: %v", err)
	}
	return name
}

/* ------------------------------ proposing -------------------------------- */

func TestProposesAWeakLinkOnAMatchingName(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	g := igaFixture{provFixture: f, bm: services.NewIGABridgeManager(gormFor(t, f.raw))}
	g.igaAgent = uuid.New()
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
		g.igaAgent, f.ws, name)

	link, err := g.bm.ProposeForAgent(f.ws, f.agent)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if link == nil {
		t.Fatal("expected a proposal for an exactly matching display name")
	}
	if link.IGAAgentID != g.igaAgent {
		t.Errorf("linked to the wrong canonical agent: %s", link.IGAAgentID)
	}
	if link.State != models.IGALinkProposed {
		t.Errorf("state = %q, want %q — an automatic link must never start accepted",
			link.State, models.IGALinkProposed)
	}
	if link.Strength != models.IGALinkWeak {
		t.Errorf("strength = %q: a name match is not an identifier, so it cannot be strong",
			link.Strength)
	}
	if link.JoinKey == "" {
		t.Error("join_key is empty: a reviewer given no evidence can only rubber-stamp")
	}
	if link.Decided {
		t.Error("a fresh proposal must not report as decided")
	}
}

// Names are normalised, so "Research Agent" and "research-agent" correlate.
func TestNameMatchingIsNormalised(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	g := igaFixture{provFixture: f, bm: services.NewIGABridgeManager(gormFor(t, f.raw))}
	// Same name, deliberately re-cased and re-punctuated.
	noisy := ""
	for _, r := range name {
		if r == '-' || r == '_' {
			noisy += " "
			continue
		}
		noisy += string(r)
	}
	g.igaAgent = uuid.New()
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
		g.igaAgent, f.ws, " "+noisy+" ")

	link, err := g.bm.ProposeForAgent(f.ws, f.agent)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if link == nil {
		t.Fatalf("no proposal: %q should normalise onto %q", noisy, name)
	}
}

// THE IMPORTANT NEGATIVE. Two canonical agents sharing a name makes the match a
// coin flip, so proposing either would dress a guess as evidence. Proposing
// nothing leaves the sighting visibly unlinked, which is honest and still
// actionable.
func TestAmbiguousNameProposesNothing(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	bm := services.NewIGABridgeManager(gormFor(t, f.raw))
	for i := 0; i < 2; i++ {
		exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
			uuid.New(), f.ws, name)
	}

	link, err := bm.ProposeForAgent(f.ws, f.agent)
	if err != nil {
		t.Fatalf("an ambiguous match is not an error: %v", err)
	}
	if link != nil {
		t.Errorf("proposed %s despite two candidates sharing the name — that is a "+
			"guess presented as a correlation", link.IGAAgentID)
	}
}

func TestNoMatchProposesNothing(t *testing.T) {
	f := newIGAFixture(t, "something-completely-different")
	link, err := f.bm.ProposeForAgent(f.ws, f.agent)
	if err != nil {
		t.Fatalf("no match is not an error: %v", err)
	}
	if link != nil {
		t.Errorf("unexpected proposal to %s", link.IGAAgentID)
	}
}

// A retired canonical agent must not be proposed: it would send a reviewer to
// resurrect something deliberately closed.
func TestRetiredCanonicalAgentIsNotProposed(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	bm := services.NewIGABridgeManager(gormFor(t, f.raw))
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name, lifecycle)
	                VALUES ($1,$2,$3,'retired')`, uuid.New(), f.ws, name)

	link, err := bm.ProposeForAgent(f.ws, f.agent)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if link != nil {
		t.Error("a retired canonical agent must not be proposed")
	}
}

/* ------------------------------- deciding -------------------------------- */

func TestAcceptingALinkRecordsTheDecider(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	bm := services.NewIGABridgeManager(gormFor(t, f.raw))
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
		uuid.New(), f.ws, name)
	link, err := bm.ProposeForAgent(f.ws, f.agent)
	if err != nil || link == nil {
		t.Fatalf("propose: %v (link=%v)", err, link)
	}

	who := uuid.New()
	out, err := bm.Decide(f.ws, f.agent, models.IGALinkAccepted, &who, link.Version)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if out.State != models.IGALinkAccepted {
		t.Errorf("state = %q", out.State)
	}
	if out.DecidedBy == nil || *out.DecidedBy != who {
		t.Error("the decider must be recorded — the DB CHECK depends on it for a weak link")
	}
	if out.DecidedAt == nil {
		t.Error("decided_at must be stamped")
	}
	if out.Version <= link.Version {
		t.Errorf("version must advance on a decision: %d -> %d", link.Version, out.Version)
	}
	if !out.Decided {
		t.Error("a decided link must report as decided")
	}
}

// An unattributable decision is refused for BOTH directions. The DB CHECK only
// covers accepts; "who decided these are not the same agent" is just as much a
// governance question as the affirmative.
func TestADecisionMustBeAttributable(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	bm := services.NewIGABridgeManager(gormFor(t, f.raw))
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
		uuid.New(), f.ws, name)
	link, _ := bm.ProposeForAgent(f.ws, f.agent)
	if link == nil {
		t.Fatal("setup: no proposal")
	}

	for _, d := range []string{models.IGALinkAccepted, models.IGALinkRejected} {
		if _, err := bm.Decide(f.ws, f.agent, d, nil, link.Version); err == nil {
			t.Errorf("%s with no decider must be refused", d)
		}
	}
}

// Optimistic concurrency, matching the iga_* decision routes: whoever reads
// second and decides against a stale version loses.
func TestAStaleDecisionIsRejected(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	bm := services.NewIGABridgeManager(gormFor(t, f.raw))
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
		uuid.New(), f.ws, name)
	link, _ := bm.ProposeForAgent(f.ws, f.agent)
	if link == nil {
		t.Fatal("setup: no proposal")
	}

	who := uuid.New()
	if _, err := bm.Decide(f.ws, f.agent, models.IGALinkRejected, &who, link.Version); err != nil {
		t.Fatalf("first decision: %v", err)
	}
	// Second reviewer, holding the version they read before the first decision.
	if _, err := bm.Decide(f.ws, f.agent, models.IGALinkAccepted, &who, link.Version); err == nil {
		t.Fatal("a decision on a stale version must be refused, not silently win")
	}
}

// A decided link is never re-proposed. Without this the reviewer would be asked
// the same rejected question on every sighting.
func TestADecidedLinkIsNotReProposed(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	bm := services.NewIGABridgeManager(gormFor(t, f.raw))
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
		uuid.New(), f.ws, name)
	link, _ := bm.ProposeForAgent(f.ws, f.agent)
	if link == nil {
		t.Fatal("setup: no proposal")
	}
	who := uuid.New()
	if _, err := bm.Decide(f.ws, f.agent, models.IGALinkRejected, &who, link.Version); err != nil {
		t.Fatalf("reject: %v", err)
	}

	again, err := bm.ProposeForAgent(f.ws, f.agent)
	if err != nil {
		t.Fatalf("re-propose: %v", err)
	}
	if again == nil || again.State != models.IGALinkRejected {
		t.Fatalf("a rejected link must stay rejected, got %v", again)
	}
}

/* ------------------------------- scoping --------------------------------- */

func TestProposalsAreWorkspaceScoped(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	bm := services.NewIGABridgeManager(gormFor(t, f.raw))
	// A canonical agent with the same name, in a DIFFERENT workspace.
	other := uuid.New()
	exec(t, f.raw, `INSERT INTO workspaces (id, name) VALUES ($1, 'other')`, other)
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
		uuid.New(), other, name)

	link, err := bm.ProposeForAgent(f.ws, f.agent)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if link != nil {
		t.Error("correlated across a workspace boundary — that leaks one tenant's " +
			"estate into another's inventory")
	}
}

func TestProposalQueueListsOnlyUndecided(t *testing.T) {
	f := newProvFixture(t)
	name := agentName(t, f)
	bm := services.NewIGABridgeManager(gormFor(t, f.raw))
	exec(t, f.raw, `INSERT INTO iga_agents (id, workspace_id, display_name) VALUES ($1,$2,$3)`,
		uuid.New(), f.ws, name)
	link, _ := bm.ProposeForAgent(f.ws, f.agent)
	if link == nil {
		t.Fatal("setup: no proposal")
	}

	rows, total, err := bm.ListProposals(f.ws, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(rows) != 1 {
		t.Fatalf("expected 1 pending proposal, got %d", total)
	}

	who := uuid.New()
	if _, err := bm.Decide(f.ws, f.agent, models.IGALinkAccepted, &who, link.Version); err != nil {
		t.Fatalf("accept: %v", err)
	}
	_, total, err = bm.ListProposals(f.ws, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 0 {
		t.Errorf("a decided link must leave the reviewer queue, still showing %d", total)
	}
}
