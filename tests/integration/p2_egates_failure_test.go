package integration

// §7.1 E9 (collection fails and relationships are retained) and E10 (a shared
// object survives one source dropping it): the backend halves, through the
// real /coverage, list, detail, graph and evidence routes over the §7.1 lab.
// The real lab removes permissions by editing the discovery role's
// CloudFormation stack and restoring it; here the fakes refuse the same calls
// with AWS's own AccessDenied. What the console draws -- the graph unchanged
// with stale markers, coverage naming the call -- is M3's Playwright run.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// egatesIAMCalls are the IAM operations the scanners call: "remove IAM
// permissions from the discovery role" refuses every one of them.
var egatesIAMCalls = []string{"GetAccountAuthorizationDetails", "ListAccessKeys", "GetAccessKeyLastUsed",
	"GetPolicy", "GetPolicyVersion", "ListOpenIDConnectProviders"}

// egatesEdgeRow is one edge or support row of the workspace, for comparing
// two points of a scenario.
type egatesEdgeRow struct {
	ID              uuid.UUID
	Kind            string
	State           string
	ValidTo         *time.Time
	LastConfirmedAt *time.Time
}

// egatesEdgeRows reads every relationship, assignment, grant and support row
// of the workspace by id.
func egatesEdgeRows(t *testing.T, l *p2Lab) map[uuid.UUID]egatesEdgeRow {
	t.Helper()
	var rows []egatesEdgeRow
	if err := l.db.Raw(`
	    SELECT id, 'relationship:' || relationship_type AS kind, state, valid_to, last_confirmed_at FROM iga_relationship WHERE workspace_id = ?
	    UNION ALL SELECT id, 'assignment', state, valid_to, last_confirmed_at FROM iga_policy_assignment WHERE workspace_id = ?
	    UNION ALL SELECT id, 'grant', state, valid_to, last_confirmed_at FROM iga_access_edges WHERE workspace_id = ? AND provider = 'aws'
	    UNION ALL SELECT id, 'support:' || CASE WHEN identity_account_id IS NOT NULL THEN 'identity'
	                                          WHEN workload_id IS NOT NULL THEN 'workload'
	                                          WHEN resource_id IS NOT NULL THEN 'resource'
	                                          WHEN entitlement_id IS NOT NULL THEN 'statement'
	                                          ELSE 'policy' END,
	                     state, NULL::timestamptz, last_confirmed_at FROM iga_object_support WHERE workspace_id = ?`,
		l.ws, l.ws, l.ws, l.ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read edges: %v", err)
	}
	out := map[uuid.UUID]egatesEdgeRow{}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out
}

// egatesCoverageSurface is one surface of one account on /coverage.
func egatesCoverageSurface(t *testing.T, api *readAPI, a *egatesAcct, surface string) map[string]any {
	t.Helper()
	s, _ := s2Surface(t, s2CoverageAccount(t, api, "", a.p2Account), surface).(map[string]any)
	return s
}

// egatesNoGuessedPermission fails when a coverage entry names a permission
// to grant (§2.14.13, E9 "coverage invents a permission name").
func egatesNoGuessedPermission(t *testing.T, what string, v any) {
	t.Helper()
	raw := strings.ToLower(egatesJSON(v))
	for _, w := range []string{`"permission`, `"missing`, `"required_permission`, `"grant_permission`} {
		if strings.Contains(raw, w) {
			t.Errorf("%s names a guessed permission (%s): %s", what, w, egatesJSON(v))
		}
	}
}

// E9 (a). IAM permissions removed from A's discovery role; rescan; restore.
// Database: zero rows ended; the IAM partitions stale with last_confirmed_at
// unchanged. API: /coverage reports each denied surface with the refused call
// and AWS's code, and prevents surface_denied -- never a guessed permission;
// the lists carry the gap in meta.coverage; affected rows and grants read
// state stale with a stale_reason and a surface_denied limitation; the graph
// is the same graph, marked stale. Restored: current again, the same ids.
//
// Safeguards (mutation-checked): an edge partition whose required surface was
// not reached is never ended (canEnd); a stale row's last_confirmed_at is not
// moved by a run that could not read it.
func TestP2EgatesE9aIAMDeniedRetainsEverything(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e9a", true)
	a := egatesProduction(t, l)
	run1 := egatesCycle(l, a)
	pub1 := egatesPublicationOf(t, l, run1.ID)
	api := l.api()
	w := egatesWorkload(t, l, "ticket-tools", accountA)
	role := egatesIdentity(t, l, egatesSharedRole)
	ticketGrant := evidenceGrant(t, l, egatesSharedRole, egatesTicketRead, "ReadTickets")
	before := egatesEdgeRows(t, l)
	graphBefore := egatesGet(t, api, "/graph"+qs("root", w, "direction", "forward"))

	for _, op := range egatesIAMCalls {
		a.iam.fail[op] = denied("iam:" + op)
	}
	run2 := egatesCycle(l, a)
	pub2 := egatesPublicationOf(t, l, run2.ID)

	// Database: nothing ended; every IAM-backed row stale, not re-confirmed.
	after := egatesEdgeRows(t, l)
	if len(after) != len(before) {
		t.Errorf("rows %d -> %d: a denied scan added or removed edges", len(before), len(after))
	}
	stale := map[string]int{}
	for id, b := range before {
		n := after[id]
		if b.State != models.RelEnded && n.State == models.RelEnded {
			t.Errorf("%s %s ENDED under a denied scan", b.Kind, id)
		}
		if n.State == models.RelStale {
			stale[b.Kind]++
			if (b.LastConfirmedAt == nil) != (n.LastConfirmedAt == nil) ||
				(b.LastConfirmedAt != nil && !b.LastConfirmedAt.Equal(*n.LastConfirmedAt)) {
				t.Errorf("%s %s is stale but its last_confirmed_at moved %v -> %v", b.Kind, id, b.LastConfirmedAt, n.LastConfirmedAt)
			}
		}
	}
	for _, kind := range []string{"assignment", "grant", "support:identity", "support:policy", "support:statement", "relationship:member_of"} {
		var total int
		for _, b := range before {
			if b.Kind == kind && b.State != models.RelEnded {
				total++
			}
		}
		if total == 0 || stale[kind] != total {
			t.Errorf("%s rows stale = %d of %d, want every one (the IAM partitions)", kind, stale[kind], total)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws' AND lifecycle <> 'active'`, l.ws); n != 0 {
		t.Errorf("%d identities retired by a denied scan", n)
	}

	// /coverage: each denied listing, the call AWS refused, its code.
	// One listing per filter (D-48), so the call names its filter.
	for s, filter := range map[string]string{models.SurfaceIAMRoles: "Roles", models.SurfaceIAMUsers: "Users",
		models.SurfaceIAMGroups: "Groups", models.SurfaceIAMPolicies: "LocalManagedPolicy"} {
		cov := egatesCoverageSurface(t, api, a, s)
		if digs(cov, "state") != models.CloudCoverageDenied || digs(cov, "api") != "iam:GetAccountAuthorizationDetails ("+filter+")" ||
			digs(cov, "error_code") != "AccessDenied" || digs(cov, "prevents") != "surface_denied" ||
			digs(cov, "run") != refOf("cloud_scan_run", run2.ID) || digs(cov, "since_run") != refOf("cloud_scan_run", run2.ID) ||
			dig(cov, "count") != nil || strings.Contains(digs(cov, "error"), "could not be assumed") ||
			// D-72: since is the published_at of the first run of the
			// unbroken streak -- this one.
			digs(cov, "since") != s2TS(run2.PublishedAt) ||
			// No invented remedy: the only fix the evidence supports is
			// selecting a region (§2.14.13), never a permission to grant.
			dig(cov, "fix") != nil {
			t.Errorf("/coverage %s = %s, want denied by iam:GetAccountAuthorizationDetails (%s), AccessDenied, in run %s since %s, no fix",
				s, egatesJSON(cov), filter, run2.ID, s2TS(run2.PublishedAt))
		}
		egatesNoGuessedPermission(t, "/coverage "+s, cov)
	}
	// The lists say what the gap affects.
	ids := egatesGet(t, api, "/identities"+qs("q", egatesSharedRole))
	var rolesGap map[string]any
	for _, c := range digl(ids, "meta", "coverage") {
		if digs(c, "surface") == models.SurfaceIAMRoles && digs(c, "account_id") == accountA {
			rolesGap = c.(map[string]any)
		}
	}
	if rolesGap == nil || digs(rolesGap, "state") != models.CloudCoverageDenied || digs(rolesGap, "affects") == "" {
		t.Errorf("/identities meta.coverage = %s, want A's iam_roles denied with what it affects", egatesJSON(dig(ids, "meta", "coverage")))
	}
	egatesNoGuessedPermission(t, "/identities meta.coverage", dig(ids, "meta", "coverage"))
	// D-73: each list names the gaps that bear on IT -- resources the managed
	// policy listing; the role's own detail its own partition's surface; the
	// workload list none of IAM's (its rows are not IAM claims), so it raises
	// no banner the data does not support.
	for what, c := range map[string]struct {
		body    map[string]any
		surface string
		want    bool
	}{
		"/resources":            {egatesGet(t, api, "/resources"), models.SurfaceIAMPolicies, true},
		"SharedToolRole detail": {egatesGet(t, api, egatesRoute(t, role)), models.SurfaceIAMRoles, true},
		"/workloads":            {egatesGet(t, api, "/workloads"), "iam_", false},
	} {
		var hit map[string]any
		for _, n := range digl(c.body, "meta", "coverage") {
			if digs(n, "account_id") == accountA && strings.HasPrefix(digs(n, "surface"), c.surface) {
				hit = n.(map[string]any)
			}
		}
		if c.want && (hit == nil || digs(hit, "state") != models.CloudCoverageDenied || digs(hit, "affects") == "") {
			t.Errorf("%s meta.coverage = %s, want A's %s denied with what it affects", what, egatesJSON(dig(c.body, "meta", "coverage")), c.surface)
		}
		if !c.want && hit != nil {
			t.Errorf("%s meta.coverage = %s, want no IAM gap: it bears on no workload row (D-73)", what, egatesJSON(dig(c.body, "meta", "coverage")))
		}
		egatesNoGuessedPermission(t, what+" meta.coverage", dig(c.body, "meta", "coverage"))
	}
	rows := digl(ids, "data")
	if len(rows) != 1 || digs(rows[0], "ref") != role || digs(rows[0], "state") != models.RelStale ||
		digs(rows[0], "lifecycle") != models.IGALifecycleActive {
		t.Fatalf("/identities?q=SharedToolRole = %s, want the role, active and stale", egatesJSON(rows))
	}
	if !egatesHasReason(digl(rows[0], "stale_reason"), accountA, models.SurfaceIAMRoles, models.CloudCoverageDenied) {
		t.Errorf("SharedToolRole stale_reason = %s, want A's iam_roles denied", egatesJSON(dig(rows[0], "stale_reason")))
	}
	// The workload's grant lines: kept, stale, saying why.
	lines := egatesTicketsLines(t, api, w, false)
	if len(lines) != 2 {
		t.Fatalf("support-tickets/* lines under a denied scan = %s, want both, kept", egatesJSON(lines))
	}
	for name, ln := range lines {
		if digs(ln, "state") != models.RelStale || len(digl(ln, "stale_reason")) == 0 {
			t.Errorf("%s line = %s, want stale with a stale_reason", name, egatesJSON(ln))
		}
	}
	// The graph: the same nodes and edges, the grants stale and marked.
	graphAfter := egatesGet(t, api, "/graph"+qs("root", w, "direction", "forward"))
	if b, a := egatesGraphShape(t, graphBefore), egatesGraphShape(t, graphAfter); b != a {
		t.Errorf("the graph changed under a denied scan:\n before %s\n after  %s", b, a)
	}
	staleGrants := graphEdgesOfKind(graphEdges(t, digl(graphAfter, "data", "edges")), "grant")
	if len(staleGrants) != 2 {
		t.Errorf("graph grants under a denied scan = %+v, want TicketRead's and ToolboxRead's, kept", staleGrants)
	}
	for _, e := range staleGrants {
		if e.State != models.RelStale || graphLim(e.Limitations, "surface_denied") == nil {
			t.Errorf("graph grant %s = state %s limitations %v, want stale with surface_denied", e.Claim, e.State, e.Limitations)
		}
	}
	// Evidence: stale since this run, confirmed last by the first, and a
	// surface_denied limitation naming the account and surface.
	ev := evidenceGet(t, api, ticketGrant)
	if digs(ev, "data", "status", "lifecycle") != models.RelStale || digs(ev, "data", "status", "collection") != "stale" ||
		digs(ev, "data", "freshness", "stale_since") != s2TS(&pub2.PublishedAt) ||
		digs(ev, "data", "freshness", "last_confirmed_at") != s2TS(&pub1.PublishedAt) {
		t.Errorf("evidence under a denied scan = status %s freshness %s, want stale since %s, last confirmed %s",
			egatesJSON(dig(ev, "data", "status")), egatesJSON(dig(ev, "data", "freshness")), s2TS(&pub2.PublishedAt), s2TS(&pub1.PublishedAt))
	}
	lim := evidenceLim(ev, "surface_denied")
	if lim == nil || digs(lim, "account_id") != accountA || digs(lim, "state") != models.CloudCoverageDenied {
		t.Errorf("evidence limitations = %v, want surface_denied for A", evidenceCodes(ev))
	}
	egatesNoGuessedPermission(t, "evidence", dig(ev, "data", "limitations"))

	// Restored: the same rows, current again, confirmed by this run.
	for _, op := range egatesIAMCalls {
		delete(a.iam.fail, op)
	}
	run3 := egatesCycle(l, a)
	restored := egatesEdgeRows(t, l)
	for id, b := range before {
		n, ok := restored[id]
		if !ok || n.State != b.State {
			t.Errorf("after restoring: %s %s is %q, want %q (the same row)", b.Kind, id, n.State, b.State)
		}
	}
	if len(restored) != len(before) {
		t.Errorf("after restoring: %d rows, want the original %d (no new ids)", len(restored), len(before))
	}
	if cov := egatesCoverageSurface(t, api, a, models.SurfaceIAMRoles); digs(cov, "state") != models.CloudCoverageReached ||
		digs(cov, "since_run") != refOf("cloud_scan_run", run3.ID) || dig(cov, "prevents") != nil {
		t.Errorf("/coverage iam_roles after restoring = %s, want reached since run %s", egatesJSON(cov), run3.ID)
	}
	if ev := evidenceGet(t, api, ticketGrant); digs(ev, "data", "status", "lifecycle") != models.RelCurrent ||
		dig(ev, "data", "freshness", "stale_since") != nil || evidenceLim(ev, "surface_denied") != nil {
		t.Errorf("evidence after restoring = %s", egatesJSON(dig(ev, "data")))
	}
}

// egatesHasReason reports whether a stale_reason list names the surface.
func egatesHasReason(reasons []any, account, surface, state string) bool {
	for _, r := range reasons {
		if digs(r, "account_id") == account && digs(r, "surface") == surface && digs(r, "state") == state {
			return true
		}
	}
	return false
}

// egatesGraphShape is a graph response's node refs and edge claims, sorted:
// what is drawn, without its states.
func egatesGraphShape(t *testing.T, body map[string]any) string {
	t.Helper()
	var parts []string
	for ref := range graphNodes(t, digl(body, "data", "nodes")) {
		parts = append(parts, "n "+ref)
	}
	for _, e := range graphEdges(t, digl(body, "data", "edges")) {
		parts = append(parts, "e "+e.Claim+" "+e.From+">"+e.To)
	}
	return strings.Join(egatesSorted(parts), "; ")
}

// egatesAWSManaged is E9(b)'s stand-in for an unreadable TicketRead (D-51):
// an attached AWS-managed policy naming the same bucket, and a second one that
// only it names.
const egatesAWSManaged = "arn:aws:iam::aws:policy/SupportTicketsReadOnly"

// E9 (b). In ONE change: GetPolicyVersion denied on TicketRead, and
// ToolboxRead detached; rescan.
//
// As written, E9(b) cannot make TicketRead unreadable: TicketRead is
// customer-managed, and after T3.1 its document arrives in the
// LocalManagedPolicy listing of GetAccountAuthorizationDetails, so a
// GetPolicyVersion denial never reaches it (D-51, raised). The test asserts
// what the backend must do with the literal action -- TicketRead stays
// CURRENT, never stale on a read that succeeded -- and runs the scenario's
// point on D-51's substitute, an attached AWS-managed policy whose
// GetPolicyVersion is denied in the same change: its grants and statements
// stale, the resource only it names kept (stale), ToolboxRead's assignment
// and grant ended, and /coverage naming the unreadable document and the call.
//
// Safeguards (mutation-checked): one unreadable document keeps its own
// partition stale without vetoing the account (a detach in the same run still
// ends).
func TestP2EgatesE9bUnreadableDocumentAndDetachInOneRun(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e9b", true)
	a := egatesProduction(t, l)
	a.iam.managedPolicies[egatesAWSManaged] = evidenceDoc(`{"Sid":"ReadSupport","Effect":"Allow","Action":"s3:GetObject",` +
		`"Resource":["` + egatesTickets + `","arn:aws:s3:::ticket-archive/*"]}`)
	a.attach(egatesSharedRole, egatesAWSManaged)
	egatesCycle(l, a)
	api := l.api()
	w := egatesWorkload(t, l, "ticket-tools", accountA)
	tickets := egatesResource(t, l, egatesTickets)
	archive := egatesResource(t, l, "arn:aws:s3:::ticket-archive/*")
	managedGrant := evidenceGrant(t, l, egatesSharedRole, "SupportTicketsReadOnly", "ReadSupport")

	refused := &smithy.OperationError{ServiceID: "IAM", OperationName: "GetPolicyVersion",
		Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform iam:GetPolicyVersion"}}
	a.iam.failPolicyVersion[a.policyARN(egatesTicketRead)] = refused
	a.iam.failPolicyVersion[egatesAWSManaged] = refused
	a.detach(egatesSharedRole, a.policyARN(egatesToolbox))
	run := egatesCycle(l, a)

	// Database.
	g := l.grants()
	if tr := grantsOf(g, egatesTicketRead); len(tr) != 1 || tr[0].State != models.RelCurrent {
		t.Errorf("TicketRead grants = %+v, want CURRENT: its document came in the authorization details (D-51)", tr)
	}
	if mg := grantsOf(g, "SupportTicketsReadOnly"); len(mg) != 1 || mg[0].State != models.RelStale || mg[0].ValidTo != nil {
		t.Errorf("unreadable policy's grants = %+v, want stale, never ended", mg)
	}
	if tb := grantsOf(g, egatesToolbox); len(tb) != 1 || tb[0].State != models.RelEnded || tb[0].ValidTo == nil {
		t.Errorf("detached ToolboxRead grants = %+v, want ended", tb)
	}
	if asg := l.assignments(egatesToolbox); len(asg) != 1 || asg[0].State != models.RelEnded || asg[0].EndedReason != models.EndedNotSeen {
		t.Errorf("ToolboxRead assignment = %+v, want ended not_seen", asg)
	}
	if asg := l.assignments("SupportTicketsReadOnly"); len(asg) != 1 || asg[0].State != models.RelCurrent {
		t.Errorf("unreadable policy's assignment = %+v, want current (attachments are read independently)", asg)
	}
	stmt := refUUID(t, graphStatementOf(t, l, "SupportTicketsReadOnly"))
	if s := l.supportOf("entitlement_id", stmt)[a.conn]; s != models.RelStale {
		t.Errorf("unreadable statement support = %q, want stale", s)
	}
	if s := l.supportOf("resource_id", refUUID(t, archive))[a.conn]; s != models.RelStale {
		t.Errorf("ticket-archive/* (named only by the unreadable document) support = %q, want stale", s)
	}

	// /coverage: the one unreadable document, with the call, and TicketRead
	// not among them.
	docs := egatesCoverageSurface(t, api, a, models.SurfacePolicyDocuments)
	if digs(docs, "state") != models.CloudCoveragePartial || digs(docs, "prevents") != "surface_partial" ||
		digs(docs, "run") != refOf("cloud_scan_run", run.ID) {
		t.Errorf("/coverage policy_documents = %s, want partial in run %s", egatesJSON(docs), run.ID)
	}
	items := digl(docs, "items")
	if len(items) != 1 || !strings.Contains(egatesJSON(items[0]), "SupportTicketsReadOnly") ||
		!strings.Contains(egatesJSON(items[0]), "GetPolicyVersion") {
		t.Errorf("/coverage policy_documents items = %s, want exactly the AWS-managed document and the refused call", egatesJSON(items))
	}
	if strings.Contains(egatesJSON(docs), egatesTicketRead) {
		t.Errorf("/coverage names TicketRead as unreadable, but its document was read: %s", egatesJSON(docs))
	}
	egatesNoGuessedPermission(t, "/coverage policy_documents", docs)
	if roles := egatesCoverageSurface(t, api, a, models.SurfaceIAMPolicies); digs(roles, "state") != models.CloudCoverageReached {
		t.Errorf("/coverage iam_policies = %s, want reached: one document does not veto the listing", egatesJSON(roles))
	}

	// The read APIs: the unreadable grant kept and stale, the detached one
	// gone, TicketRead current.
	lines := egatesTicketsLines(t, api, w, false)
	if len(lines) != 2 || digs(lines[egatesTicketRead], "state") != models.RelCurrent ||
		digs(lines["SupportTicketsReadOnly"], "state") != models.RelStale || lines[egatesToolbox] != nil {
		t.Errorf("support-tickets/* lines = %s, want TicketRead current, SupportTicketsReadOnly stale, ToolboxRead gone", egatesJSON(lines))
	}
	if !egatesHasReason(digl(lines["SupportTicketsReadOnly"], "stale_reason"), accountA, models.SurfacePolicyDocuments, models.CloudCoveragePartial) {
		t.Errorf("stale line reason = %s, want A's policy_documents", egatesJSON(dig(lines["SupportTicketsReadOnly"], "stale_reason")))
	}
	ev := evidenceGet(t, api, managedGrant)
	if digs(ev, "data", "status", "lifecycle") != models.RelStale || evidenceLim(ev, "surface_partial") == nil {
		t.Errorf("unreadable grant evidence = status %s limitations %v, want stale with surface_partial",
			egatesJSON(dig(ev, "data", "status")), evidenceCodes(ev))
	}
	if d := egatesGet(t, api, egatesRoute(t, archive)); digs(d, "data", "lifecycle") != models.IGALifecycleActive ||
		digs(d, "data", "state") != models.RelStale {
		t.Errorf("ticket-archive/* = %s, want active and stale", egatesJSON(dig(d, "data")))
	}
	if p := egatesGet(t, api, "/graph/path"+qs("from", w, "to", tickets)); digs(p, "data", "outcome") != "found" ||
		len(digl(p, "data", "paths")) != 2 {
		t.Errorf("paths to support-tickets/* = %s, want TicketRead's and the stale one's", egatesJSON(dig(p, "data")))
	}
}

// E10. A and B both name support-tickets/*; B's SandboxTickets policy is
// removed and B rescanned. Database: B's support row for the reference ended,
// A's current, the resource active, A's grants unchanged. API: the resource's
// sources show A current and B ended; it is still listed; Access shows A's
// grants and never B's ended one by default; A's grants still name
// support-tickets/*, never "*".
//
// Safeguards (mutation-checked): a pass ends only its OWN connector's support
// rows (its partition's connector and key scope the end); a node retires only
// when no support row is left.
func TestP2EgatesE10SharedObjectSurvivesOneSource(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e10", true)
	a := egatesProduction(t, l)
	b := egatesSandbox(t, l)
	egatesCycle(l, a)
	egatesCycle(l, b)
	api := l.api()
	tickets := egatesResource(t, l, egatesTickets)
	aGrants := map[uuid.UUID]grantRow{}
	for _, g := range append(grantsOf(l.grants(), egatesTicketRead), grantsOf(l.grants(), egatesToolbox)...) {
		aGrants[g.ID] = g
	}
	confirmedBefore := egatesEdgeRows(t, l)

	d := egatesGet(t, api, egatesRoute(t, tickets))
	if srcs := digl(d, "data", "sources"); len(srcs) != 2 {
		t.Fatalf("setup: support-tickets/* sources = %s, want A and B", egatesJSON(srcs))
	}

	// B's policy naming the bucket is deleted.
	sandbox := b.policyARN("SandboxTickets")
	b.detach("data-reader", sandbox)
	delete(b.iam.managedPolicies, sandbox)
	runB := egatesCycle(l, b)

	// Database.
	sup := l.supportOf("resource_id", refUUID(t, tickets))
	if sup[a.conn] != models.RelCurrent || sup[b.conn] != models.RelEnded {
		t.Errorf("support-tickets/* support = %v, want A current and B ended", sup)
	}
	if _, life := l.resourceID(egatesTickets); life != models.IGALifecycleActive {
		t.Errorf("support-tickets/* is %s, want active", life)
	}
	for id, g0 := range aGrants {
		var g grantRow
		l.db.Raw(`SELECT id, state, valid_to FROM iga_access_edges WHERE id = ?`, id).Scan(&g)
		if g.State != g0.State || g.ValidTo != nil {
			t.Errorf("A's grant %s (%s) = %s after B's rescan, want unchanged %s", id, g0.Policy, g.State, g0.State)
		}
	}
	// B's pass does not touch A's claims: not re-confirmed, not moved.
	confirmedAfter := egatesEdgeRows(t, l)
	for id := range aGrants {
		b0, b1 := confirmedBefore[id], confirmedAfter[id]
		if b0.LastConfirmedAt == nil || b1.LastConfirmedAt == nil || !b0.LastConfirmedAt.Equal(*b1.LastConfirmedAt) {
			t.Errorf("A's grant %s last_confirmed_at %v -> %v across B's pass", id, b0.LastConfirmedAt, b1.LastConfirmedAt)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_entitlement_target et JOIN iga_resources r ON r.workspace_id = et.workspace_id
	                  AND r.id = et.resource_id JOIN iga_entitlements e ON e.workspace_id = et.workspace_id AND e.id = et.entitlement_id
	                  JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                  WHERE et.workspace_id = ? AND p.display_name IN ('TicketRead','ToolboxRead') AND r.display_name = ?`,
		l.ws, egatesTickets); n != 2 {
		t.Errorf("A's statements name support-tickets/* %d times, want 2 (never re-pointed to *)", n)
	}

	// API: sources A current, B ended.
	d = egatesGet(t, api, egatesRoute(t, tickets))
	bySrc := map[string]map[string]any{}
	for _, s := range digl(d, "data", "sources") {
		bySrc[digs(s, "integration")] = s.(map[string]any)
	}
	sa, sb := bySrc[refOf("cloud_connector", a.conn)], bySrc[refOf("cloud_connector", b.conn)]
	pubB := egatesPublicationOf(t, l, runB.ID)
	if len(bySrc) != 2 || digs(sa, "state") != models.RelCurrent || digs(sa, "account", "id") != accountA ||
		digs(sb, "state") != models.RelEnded || digs(sb, "account", "id") != accountB || digs(sb, "ended_reason") != models.EndedNotSeen {
		t.Errorf("sources after B dropped it = %s, want A current, B ended not_seen", egatesJSON(dig(d, "data", "sources")))
	}
	if digs(d, "data", "lifecycle") != models.IGALifecycleActive || digs(d, "data", "state") != models.RelCurrent ||
		num(d, "data", "named_by_count", "value") != 2 {
		t.Errorf("support-tickets/* detail = %s, want active, current, named by A's two statements", egatesJSON(dig(d, "data")))
	}
	egatesMeta(t, "resource detail", d, pubB.Rev, egatesMicro(pubB.PublishedAt))
	if rows := digl(egatesGet(t, api, "/resources"+qs("q", "support-tickets")), "data"); len(rows) != 1 || digs(rows[0], "ref") != tickets {
		t.Errorf("/resources?q=support-tickets = %s, want the reference, still listed", egatesJSON(rows))
	}
	acc := egatesGet(t, api, egatesRoute(t, tickets, "/access"))
	var holders []string
	for _, r := range digl(acc, "data", "access") {
		holders = append(holders, digs(r, "holder", "name")+"/"+digs(r, "policy", "name")+"/"+digs(r, "state"))
	}
	if strings.Join(egatesSorted(holders), ",") != "SharedToolRole/TicketRead/current,SharedToolRole/ToolboxRead/current" {
		t.Errorf("support-tickets/* access = %v, want A's two grants only", holders)
	}
	ended := egatesGet(t, api, egatesRoute(t, tickets, "/access")+qs("include_ended", "true"))
	var endedB bool
	for _, r := range digl(ended, "data", "access") {
		endedB = endedB || (digs(r, "holder", "name") == "data-reader" && digs(r, "state") == models.RelEnded)
	}
	if !endedB {
		t.Errorf("include_ended access = %s, want B's data-reader grant, ended", egatesJSON(digl(ended, "data", "access")))
	}
	wa := egatesWorkload(t, l, "ticket-tools", accountA)
	var stars int
	for _, r := range digl(egatesGet(t, api, egatesRoute(t, wa, "/resources")), "data") {
		if digs(r, "resource", "text") == "*" {
			stars++
		}
	}
	if stars != 0 || len(egatesTicketsLines(t, api, wa, false)) != 2 {
		t.Errorf("A's ticket-tools resources: %d rows on *, lines %v; want support-tickets/* with its two lines and no *",
			stars, egatesTicketsLines(t, api, wa, false))
	}
	// B's side: nothing left to reach.
	wb := egatesWorkload(t, l, "ticket-tools", accountB)
	if rows := digl(egatesGet(t, api, egatesRoute(t, wb, "/resources")), "data"); len(rows) != 0 {
		t.Errorf("B's ticket-tools resources = %s, want none", egatesJSON(rows))
	}
	if code, body := api.get(egatesRoute(t, tickets) + qs("rev", graphItoa(pubB.Rev-1))); code != http.StatusConflict ||
		errCode(body) != "revision_stale" {
		t.Errorf("the resource at the previous revision = %d %v, want 409 revision_stale", code, body)
	}
}
