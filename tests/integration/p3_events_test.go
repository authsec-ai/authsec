package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// T3.20 (SPEC-iga-phase3-policy.md §7.8, §9.6, E-10; A19 events export):
// the events API and export, the event vocabulary, and the walker proving
// EVERY Phase 3 mutating route writes an iga_gov_event and an audit_events
// row.
//
// Safeguards (mutation-checked): the workspace filter of the events query;
// redaction; the walker's completeness check (a mutating route without a
// case fails it).

// GET /events: newest first, filters, cursor paging bound to the filter,
// redaction, another workspace's events invisible; GET /events/export as
// CSV and NDJSON, oldest first, complete; GET /events/kinds.
func TestP3T320EventsAPIAndExport(t *testing.T) {
	db := igaDB(t)
	api := p3NewOwnersAPI(t, db)
	g := p3NewGov(t, db, "p3notify-events")
	other := p3NewGov(t, db, "p3notify-events-other")
	p3Audit(t, db, g.ws, other.ws)
	ctx := context.Background()
	reader := api.token(g.ws, g.author, g.authorMember, "governance:read")
	admin := api.token(g.ws, g.author, g.authorMember, "governance:read iga:admin")
	otherReader := api.token(other.ws, other.author, other.authorMember, "governance:read")

	// Seed through the real writers: an owner change, a review and its
	// response, a settings change; plus one event with sensitive payload keys.
	role, rid := g.identity("EventsRole", nil)
	wl := g.workload("events-agent", &role, models.RelTypeExecutesAs)
	u1, _ := g.member("u1-events@p3notify.test", "Una One", "active")
	if code, body := api.call(http.MethodPut, "/owners", admin, map[string]any{"object_kind": "workload", "object_id": wl.String(),
		"owners": []map[string]any{{"user_id": u1.String(), "role": "accountable"}}}); code != http.StatusOK {
		t.Fatalf("PUT owners: %d %v", code, body)
	}
	rev := g.reviewVersion(nil, 1, map[string]string{"ec2": igagov.GrantAgeObservedSinceChange},
		p3RevTarget{identity: role, roleID: rid, name: "EventsRole", removed: []string{"ec2"}})
	svc := services.NewIGAGovOwnerReviewService(db)
	sync, err := svc.OpenReview(ctx, g.ws, rev.version, g.author)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Respond(ctx, g.ws, u1, sync.ReviewID, p3Ack(nil)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := services.NewGovSettingsService(db).Update(ctx, g.ws, g.author, services.GovSettingsPatch{CanaryHours: intp(12)}); err != nil {
		t.Fatal(err)
	}
	secretPayload := `{"webhook_secret":"s3cr3t","nested":{"external_id":"ext-123","email":"a@b.test","email_enabled":true},"list":[{"token":"tok"}],"keep":"visible"}`
	if err := repositories.NewIGAGovEventRepository(db).AppendTx(db, &models.IGAGovEvent{WorkspaceID: g.ws, Event: services.GovEventSettingsUpdated,
		ActorKind: models.GovActorSystem, ActorID: "test", Payload: json.RawMessage(secretPayload)}); err != nil {
		t.Fatal(err)
	}
	// The other workspace has one event of its own.
	if _, _, err := services.NewGovSettingsService(db).Update(ctx, other.ws, other.author, services.GovSettingsPatch{CanaryHours: intp(13)}); err != nil {
		t.Fatal(err)
	}
	var total int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, g.ws).Scan(&total)
	if total < 6 {
		t.Fatalf("seeded %d events", total)
	}

	events := func(q, tok string) ([]map[string]any, map[string]any) {
		t.Helper()
		code, body := api.call(http.MethodGet, "/events"+q, tok, nil)
		if code != http.StatusOK {
			t.Fatalf("GET /events%s: %d %v", q, code, body)
		}
		var out []map[string]any
		for _, e := range body["data"].([]any) {
			out = append(out, e.(map[string]any))
		}
		return out, body["meta"].(map[string]any)
	}
	all, meta := events("", reader)
	if int64(len(all)) != total || meta["next_cursor"] != nil {
		t.Fatalf("all: %d events (want %d), meta %v", len(all), total, meta)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1]["id"].(float64) <= all[i]["id"].(float64) {
			t.Fatal("events are not newest first")
		}
	}
	// Redaction.
	red := all[0]["payload"].(map[string]any)
	if red["webhook_secret"] != "[redacted]" || dig(red, "nested", "external_id") != "[redacted]" || dig(red, "nested", "email") != "[redacted]" ||
		dig(red, "nested", "email_enabled") != true || dig(red, "list", 0, "token") != "[redacted]" || red["keep"] != "visible" {
		t.Fatalf("redaction: %v", red)
	}
	// Filters.
	count := func(q string) int { e, _ := events(q, reader); return len(e) }
	if n := count("?kind=review.responded"); n != 1 {
		t.Fatalf("kind exact: %d", n)
	}
	if n := count("?kind=review.*"); n != 3 { // opened, responded, completed
		t.Fatalf("kind prefix: %d", n)
	}
	if n := count("?kind=review.opened,owners.set"); n != 2 {
		t.Fatalf("kind list: %d", n)
	}
	if n := count("?category=owner_review"); n != 3 {
		t.Fatalf("category: %d", n)
	}
	if n := count("?object_kind=review&object_id=" + sync.ReviewID.String()); n != 3 {
		t.Fatalf("object review: %d", n)
	}
	if n := count("?object_kind=policy&object_id=" + rev.policy.String()); n != 3 {
		t.Fatalf("object policy: %d", n)
	}
	if n := count("?object_kind=workload&object_id=" + wl.String()); n != 1 {
		t.Fatalf("object workload: %d", n)
	}
	if n := count("?actor=" + u1.String()); n != 2 { // review.responded and the review.completed it caused
		t.Fatalf("actor: %d", n)
	}
	if n := count("?actor_kind=system"); n < 1 {
		t.Fatalf("actor_kind: %d", n)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if n := count("?from=" + future); n != 0 {
		t.Fatalf("from future: %d", n)
	}
	if n := count("?from=" + past + "&to=" + future); int64(n) != total {
		t.Fatalf("window: %d", n)
	}
	for _, q := range []string{"?kind=Bad%20Kind", "?object_kind=review", "?object_kind=galaxy&object_id=" + uuid.NewString(),
		"?object_id=" + uuid.NewString(), "?from=yesterday", "?limit=500", "?actor_kind=robot", "?category=nope",
		"?from=" + future + "&to=" + past} {
		if code, body := api.call(http.MethodGet, "/events"+q, reader, nil); code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
			t.Fatalf("GET /events%s: %d %v", q, code, body)
		}
	}
	// Paging: 2 at a time, no overlap, the same events; the cursor is bound to its filter.
	var paged []float64
	cursor := ""
	for i := 0; i < 20; i++ {
		q := "?limit=2"
		if cursor != "" {
			q += "&cursor=" + cursor
		}
		page, m := events(q, reader)
		for _, e := range page {
			paged = append(paged, e["id"].(float64))
		}
		if m["next_cursor"] == nil {
			break
		}
		cursor = m["next_cursor"].(string)
		if i == 0 {
			if code, body := api.call(http.MethodGet, "/events?limit=2&kind=review.*&cursor="+cursor, reader, nil); code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
				t.Fatalf("cursor under another filter: %d %v", code, body)
			}
			if code, body := api.call(http.MethodGet, "/events?limit=2&cursor="+cursor, otherReader, nil); code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
				t.Fatalf("cursor in another workspace: %d %v", code, body)
			}
		}
	}
	if int64(len(paged)) != total {
		t.Fatalf("paged %d events, want %d", len(paged), total)
	}
	for i, e := range all {
		if paged[i] != e["id"].(float64) {
			t.Fatalf("page order differs at %d", i)
		}
	}
	// Another workspace sees only its own events, also when filtering by ours.
	if o, _ := events("", otherReader); len(o) != 1 || o[0]["event"] != services.GovEventSettingsUpdated {
		t.Fatalf("other workspace: %v", o)
	}
	if o, _ := events("?object_kind=review&object_id="+sync.ReviewID.String(), otherReader); len(o) != 0 {
		t.Fatalf("other workspace filtering by our review: %v", o)
	}
	if code, _ := api.call(http.MethodGet, "/events", api.token(g.ws, g.author, g.authorMember, "iga:admin"), nil); code != http.StatusForbidden {
		t.Fatalf("events without governance:read: %d", code)
	}

	// Export: CSV, oldest first, every event, redacted.
	code, hdr, raw := api.raw(http.MethodGet, "/events/export?format=csv", reader)
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") || !strings.Contains(hdr.Get("Content-Disposition"), "attachment") {
		t.Fatalf("csv export: %d %v", code, hdr)
	}
	recs, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(recs[0], ",") != strings.Join(services.GovEventCSVHeader, ",") || int64(len(recs)-1) != total {
		t.Fatalf("csv: header %v, %d rows (want %d)", recs[0], len(recs)-1, total)
	}
	prev := int64(0)
	for _, r := range recs[1:] {
		id, _ := strconv.ParseInt(r[0], 10, 64)
		if id <= prev {
			t.Fatal("csv export is not oldest first")
		}
		prev = id
		if strings.Contains(r[10], "s3cr3t") || strings.Contains(r[10], "ext-123") {
			t.Fatalf("csv export leaks a secret: %s", r[10])
		}
	}
	if recs[1][2] != "owners.set" || recs[1][3] != "ownership" {
		t.Fatalf("first exported event %v", recs[1])
	}
	// NDJSON (format=json), filtered.
	code, hdr, raw = api.raw(http.MethodGet, "/events/export?format=json&kind=review.*", reader)
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "application/x-ndjson") {
		t.Fatalf("ndjson export: %d %v", code, hdr)
	}
	var kinds []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("ndjson line %q: %v", sc.Text(), err)
		}
		kinds = append(kinds, e["event"].(string))
	}
	if strings.Join(kinds, ",") != "review.opened,review.responded,review.completed" {
		t.Fatalf("ndjson events %v", kinds)
	}
	if code, _, _ := api.raw(http.MethodGet, "/events/export?format=xml", reader); code != http.StatusBadRequest {
		t.Fatalf("format=xml: %d", code)
	}
	code, _, raw = api.raw(http.MethodGet, "/events/export?format=ndjson", otherReader)
	if code != http.StatusOK || bytes.Count(raw, []byte("\n")) != 1 {
		t.Fatalf("other workspace export: %d %s", code, raw)
	}
	// Kinds: recorded categories, and the ones not recorded yet.
	code, body := api.call(http.MethodGet, "/events/kinds", reader, nil)
	if code != http.StatusOK {
		t.Fatalf("kinds: %d %v", code, body)
	}
	rec := map[string]bool{}
	for _, c := range body["data"].(map[string]any)["categories"].([]any) {
		m := c.(map[string]any)
		rec[m["category"].(string)] = m["recorded"].(bool)
	}
	// approval / proposal are recorded since T3.11 / T3.13 (p3-wire); verification since T3.16.
	if !rec["owner_review"] || !rec["ownership"] || !rec["approval"] || !rec["proposal"] || !rec["verification"] || rec["rollout"] {
		t.Fatalf("categories %v", rec)
	}
}

func intp(v int) *int { return &v }

/* ------------------------------- vocabulary -------------------------------- */

var reEventName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$`)

// govEventNamesInSource walks package services and returns every event name
// a writer appends: the Event field of a models.IGAGovEvent literal, and the
// name argument (3rd) of the writer helpers (event, appendEvent,
// appendGovEvent) -- a string literal, a constant, or a local variable
// assigned constants in the same function.
func govEventNamesInSource(t *testing.T) map[string][]string {
	t.Helper()
	dir := filepath.Join("..", "..", "services")
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var parsed []*ast.File
	consts := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, af)
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
							v, _ := strconv.Unquote(bl.Value)
							consts[n.Name] = v
						}
					}
				}
			}
		}
	}
	out := map[string][]string{}
	add := func(name, where string) {
		if reEventName.MatchString(name) {
			out[name] = append(out[name], where)
		}
	}
	valuesOf := func(e ast.Expr, locals map[string][]string) []string {
		switch x := e.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				v, _ := strconv.Unquote(x.Value)
				return []string{v}
			}
		case *ast.Ident:
			if v, ok := consts[x.Name]; ok {
				return []string{v}
			}
			return locals[x.Name]
		}
		return nil
	}
	writers := map[string]bool{"event": true, "appendEvent": true, "appendGovEvent": true}
	for _, af := range parsed {
		for _, d := range af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			where := fset.Position(fd.Pos()).Filename + ":" + fd.Name.Name
			locals := map[string][]string{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == len(as.Rhs) {
					for i, l := range as.Lhs {
						if id, ok := l.(*ast.Ident); ok {
							locals[id.Name] = append(locals[id.Name], valuesOf(as.Rhs[i], nil)...)
						}
					}
				}
				return true
			})
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					sel, ok := x.Type.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "IGAGovEvent" {
						return true
					}
					for _, el := range x.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok {
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Event" {
								for _, v := range valuesOf(kv.Value, locals) {
									add(v, where)
								}
							}
						}
					}
				case *ast.CallExpr:
					name := ""
					switch f := x.Fun.(type) {
					case *ast.Ident:
						name = f.Name
					case *ast.SelectorExpr:
						name = f.Sel.Name
					}
					if writers[name] && len(x.Args) >= 3 {
						for _, v := range valuesOf(x.Args[2], locals) {
							add(v, where)
						}
					}
				}
				return true
			})
		}
	}
	return out
}

// Every event name a writer in package services appends is in the
// vocabulary, and every vocabulary name has a writer.
func TestP3T320EventVocabularyMatchesWriters(t *testing.T) {
	found := govEventNamesInSource(t)
	vocab := map[string]bool{}
	for _, k := range services.GovEventVocabulary {
		if vocab[k.Name] {
			t.Errorf("vocabulary lists %s twice", k.Name)
		}
		vocab[k.Name] = true
		if k.Category == "" || k.Description == "" {
			t.Errorf("vocabulary entry %s lacks a category or description", k.Name)
		}
	}
	var missing, stale []string
	for name, where := range found {
		if !vocab[name] {
			missing = append(missing, name+" ("+strings.Join(where, ", ")+")")
		}
	}
	for name := range vocab {
		if _, ok := found[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("event names written but not in the vocabulary:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("vocabulary names no writer uses: %v", stale)
	}
	if len(found) < 30 {
		t.Fatalf("the source scan found only %d names; it is not seeing the writers", len(found))
	}
}

/* --------------------------------- walker --------------------------------- */

// The walker: EVERY Phase 3 mutating route (every non-GET route of
// RegisterIGAPolicyRoutes as mounted by routes.SetupIGARoutes, and of
// RegisterEnforcementBindingRoutes) answered 2xx writes at least one
// iga_gov_event in its workspace and an audit_events row for that request.
// A mutating route with no case here fails the test, so a new route cannot
// land unaudited. Every event written is in the vocabulary.
//
// Exempt, with the reason: POST /targets/resolve is a read with a body
// (§7.2: governance:read; iga_gov_findings_controller.go: "writes neither
// iga_gov_event nor audit_events").
func TestP3T320EveryMutationAudited(t *testing.T) {
	db := igaDB(t)
	api := p3NewOwnersAPI(t, db)
	g := p3NewGov(t, db, "p3notify-walker")
	p3Audit(t, db, g.ws)
	ctx := context.Background()
	const prefix = "/api/iga/v1/policy"
	exempt := map[string]string{
		"POST " + prefix + "/targets/resolve": "a read with a body (§7.2, governance:read)",
	}
	// T3.16's §7.6 / §7.7 routes need deployments over a fake AWS account;
	// TestP3T316DeploymentRoutes calls each with a 2xx answer and asserts its
	// iga_gov_event and audit_events rows, as this walker does.
	for _, r := range []string{"/deployments/:id/resolve", "/deployments/:id/undo", "/deployments/:id/emergency-undo",
		"/deployments/:id/validations", "/deployments/:id/health-reports", "/policies/:id/remove-control",
		"/policies/:id/emergency-remove-control"} {
		exempt["POST "+prefix+r] = "audited in TestP3T316DeploymentRoutes (T3.16)"
	}

	role, rid := g.identity("WalkerRole", nil)
	w1 := g.workload("walker-agent", &role, models.RelTypeExecutesAs)
	w2 := g.workload("walker-batch", &role, models.RelTypeExecutesAs)
	u1, m1 := g.member("u1-walker@p3notify.test", "Una One", "active")
	u2, _ := g.member("u2-walker@p3notify.test", "Uli Two", "active")
	p3Manual(t, db, g, models.GovObjectWorkload, w2, u2, models.GovOwnerAccountable)
	all := "governance:read governance:author governance:approve governance:enforce iga:admin"
	adminTok := api.token(g.ws, g.author, g.authorMember, all)
	approverTok := api.token(g.ws, g.approver, g.membershipOf(g.approver), all)
	ownerTok := api.token(g.ws, u1, m1, "")

	var ownerID, ruleID, reviewID string
	type step struct {
		route string // "METHOD <registered path>"
		call  func() (method, path, tok string, body any)
		after func(body map[string]any)
	}
	steps := []step{
		{"PUT " + prefix + "/owners", func() (string, string, string, any) {
			return http.MethodPut, "/owners", adminTok, map[string]any{"object_kind": "workload", "object_id": w1.String(),
				"owners": []map[string]any{{"user_id": u1.String(), "role": "accountable"}}}
		}, func(body map[string]any) { ownerID = digs(body, "data", "owners", 0, "id") }},
		{"PATCH " + prefix + "/owners/:id", func() (string, string, string, any) {
			return http.MethodPatch, "/owners/" + ownerID, adminTok, map[string]any{"review_due_at": time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)}
		}, nil},
		{"POST " + prefix + "/owner-rules", func() (string, string, string, any) {
			return http.MethodPost, "/owner-rules", adminTok, map[string]any{"tag_key": "walker-owner"}
		}, func(body map[string]any) { ruleID = digs(body, "data", "id") }},
		{"DELETE " + prefix + "/owner-rules/:id", func() (string, string, string, any) {
			return http.MethodDelete, "/owner-rules/" + ruleID, adminTok, nil
		}, nil},
		{"POST " + prefix + "/reviews/:id/respond", func() (string, string, string, any) {
			// The review is opened by the authoring service (T3.11's propose);
			// here, by the service directly.
			rev := g.reviewVersion(nil, 1, map[string]string{"ec2": igagov.GrantAgeObservedSinceChange},
				p3RevTarget{identity: role, roleID: rid, name: "WalkerRole", removed: []string{"ec2"}})
			s, err := services.NewIGAGovOwnerReviewService(db).OpenReview(ctx, g.ws, rev.version, g.author)
			if err != nil {
				t.Fatal(err)
			}
			reviewID = s.ReviewID.String()
			return http.MethodPost, "/reviews/" + reviewID + "/respond", ownerTok, map[string]any{"response": "acknowledge"}
		}, nil},
		{"POST " + prefix + "/reviews/:id/remind", func() (string, string, string, any) {
			return http.MethodPost, "/reviews/" + reviewID + "/remind", adminTok, nil
		}, nil},
		{"POST " + prefix + "/reviews/:id/exception", func() (string, string, string, any) {
			return http.MethodPost, "/reviews/" + reviewID + "/exception", approverTok, map[string]any{"reason": "walker"}
		}, nil},
		{"PUT " + prefix + "/settings", func() (string, string, string, any) {
			return http.MethodPut, "/settings", adminTok, map[string]any{"canary_hours": 72}
		}, nil},
	}
	// The route table as production mounts it.
	registered := map[string]bool{}
	for _, r := range api.eng.Routes() {
		if strings.HasPrefix(r.Path, prefix+"/") && r.Method != http.MethodGet && r.Method != http.MethodHead {
			registered[r.Method+" "+r.Path] = true
		}
	}
	covered := map[string]bool{}
	for _, s := range steps {
		covered[s.route] = true
	}
	for r := range exempt {
		covered[r] = true
	}
	// The §7.3 / §7.5 authoring and approval routes (T3.11 / T3.13) need a
	// published revision, evidence and a live reader: they are walked by
	// TestP3T320AuthoringMutationsAudited, over the P3 evaluation lab
	// (p3-wire; a P2 lab cannot run beside this test's fixture).
	for _, r := range p3AuthoringRoutes(prefix) {
		covered[r] = true
	}
	for r := range registered {
		if !covered[r] {
			t.Errorf("mutating route %s has no audit case in the walker", r)
		}
	}
	for r := range covered {
		if !registered[r] {
			t.Errorf("walker case %s names no registered route", r)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	countEvents := func(ws uuid.UUID) int64 {
		var n int64
		db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, ws).Scan(&n)
		return n
	}
	for _, s := range steps {
		method, path, tok, body := s.call()
		before := countEvents(g.ws)
		code, resp := api.call(method, path, tok, body)
		if code < 200 || code > 299 {
			t.Fatalf("%s: %d %v", s.route, code, resp)
		}
		if countEvents(g.ws) <= before {
			t.Fatalf("%s wrote no iga_gov_event", s.route)
		}
		p3WaitAudit(t, db, g.ws, method, prefix+path)
		if s.after != nil {
			s.after(resp)
		}
	}
	vocab := map[string]bool{}
	for _, k := range services.GovEventVocabulary {
		vocab[k.Name] = true
	}
	var names []string
	db.Raw(`SELECT DISTINCT event FROM iga_gov_event WHERE workspace_id = ?`, g.ws).Scan(&names)
	for _, n := range names {
		if !vocab[n] {
			t.Errorf("event %s is not in the vocabulary", n)
		}
	}

	t.Run("enforcement binding routes", func(t *testing.T) {
		graphOn := p3GraphOn(t, db)
		gate := services.NewPolicyGate(true, "", graphOn)
		if err := gate.Verify(db); err != nil {
			t.Fatal(err)
		}
		r := newEnfRouteLab(t, gate)
		t.Cleanup(func() { db.Exec(`DELETE FROM audit_events WHERE workspace_id = ?`, r.a.ws.String()) })
		tok := r.token(t, r.a, "discovery:read governance:enforce")
		base := "/aws/connectors/" + r.a.connector.ID.String() + "/enforcement"
		const dprefix = "/authsec/discovery"
		var suffix, ext string
		bsteps := []step{
			{"POST " + dprefix + "/aws/connectors/:id/enforcement/sessions", func() (string, string, string, any) {
				return http.MethodPost, base + "/sessions", tok, map[string]any{"deployment_region": "us-east-1"}
			}, func(body map[string]any) {
				suffix, ext = digs(body, "data", "suffix"), digs(body, "data", "external_id")
			}},
			{"POST " + dprefix + "/aws/connectors/:id/enforcement", func() (string, string, string, any) {
				r.aws.deploy(t, testAccount, suffix, ext)
				return http.MethodPost, base, tok, map[string]any{
					"role_arn":          "arn:aws:iam::" + testAccount + ":role/AuthSecEnforcement-" + suffix,
					"selftest_role_arn": "arn:aws:iam::" + testAccount + ":role/AuthSecEnforcementSelfTest-" + suffix}
			}, nil},
			{"POST " + dprefix + "/aws/connectors/:id/enforcement/verify", func() (string, string, string, any) {
				return http.MethodPost, base + "/verify", tok, nil
			}, nil},
			{"DELETE " + dprefix + "/aws/connectors/:id/enforcement", func() (string, string, string, any) {
				return http.MethodDelete, base, tok, map[string]any{"reason": "walker"}
			}, nil},
		}
		reg := map[string]bool{}
		for _, rt := range r.eng.Routes() {
			if strings.Contains(rt.Path, "/enforcement") && rt.Method != http.MethodGet {
				reg[rt.Method+" "+rt.Path] = true
			}
		}
		cov := map[string]bool{}
		for _, s := range bsteps {
			cov[s.route] = true
			if !reg[s.route] {
				t.Fatalf("walker case %s names no registered route", s.route)
			}
		}
		for rt := range reg {
			if !cov[rt] {
				t.Fatalf("mutating binding route %s has no audit case", rt)
			}
		}
		for _, s := range bsteps {
			method, path, tk, body := s.call()
			before := countEvents(r.a.ws)
			code, resp := r.call(method, path, tk, body)
			if code < 200 || code > 299 {
				t.Fatalf("%s: %d %v", s.route, code, resp)
			}
			if countEvents(r.a.ws) <= before {
				t.Fatalf("%s wrote no iga_gov_event", s.route)
			}
			p3WaitAudit(t, db, r.a.ws, method, dprefix+path)
			if s.after != nil {
				s.after(resp)
			}
		}
	})
}

// p3AuthoringRoutes are the §7.3 / §7.5 mutating routes of T3.11 / T3.13.
func p3AuthoringRoutes(prefix string) []string {
	return []string{
		"POST " + prefix + "/proposals",
		"PATCH " + prefix + "/policies/:id",
		"POST " + prefix + "/policies/:id/versions/:no/propose",
		"POST " + prefix + "/policies/:id/versions/:no/approve",
		"POST " + prefix + "/policies/:id/versions",
		"POST " + prefix + "/policies/:id/versions/:no/withdraw",
		"POST " + prefix + "/policies/:id/versions/:no/reject",
		"POST " + prefix + "/policies/:id/pause",
		"POST " + prefix + "/policies/:id/resume",
		"POST " + prefix + "/policies/:id/archive",
	}
}

// The walker's authoring half (p3-wire): every §7.3 / §7.5 mutating route
// answered 2xx writes an iga_gov_event and an audit_events row, and every
// event it writes is in the vocabulary.
func TestP3T320AuthoringMutationsAudited(t *testing.T) {
	const prefix = "/api/iga/v1/policy"
	l := newP3aLab(t, "p3notify-walker-authoring")
	roleID := "AROAWALKERAUTH00001"
	l.role("WalkerAuthRole", roleID, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.publish()
	var policy string
	var intent any
	walked := map[string]bool{}
	walk := func(route string, m p3aMember, method, path string, body any) map[string]any {
		t.Helper()
		before := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, l.ws)
		code, resp := l.call(m, method, path, body)
		if code < 200 || code > 299 {
			t.Fatalf("%s: %d %v", route, code, resp)
		}
		if l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, l.ws) <= before {
			t.Fatalf("%s wrote no iga_gov_event", route)
		}
		p3WaitAudit(t, l.db, l.ws, method, prefix+path)
		walked[route] = true
		d, _ := resp["data"].(map[string]any)
		return d
	}
	d := walk("POST "+prefix+"/proposals", l.author, http.MethodPost, "/proposals",
		map[string]any{"template": "right_size_services", "keys": []any{map[string]any{"provider": "aws", "role_id": roleID}}})
	policy = d["policy"].(map[string]any)["id"].(string)
	intent = d["version"].(map[string]any)["intent"]
	pp := "/policies/" + policy
	walk("PATCH "+prefix+"/policies/:id", l.author, http.MethodPatch, pp, map[string]any{"name": "walker renamed"})
	walk("POST "+prefix+"/policies/:id/versions/:no/propose", l.author, http.MethodPost, pp+"/versions/1/propose", nil)
	walk("POST "+prefix+"/policies/:id/versions/:no/approve", l.approver, http.MethodPost, pp+"/versions/1/approve",
		p3aApproveBody(l.plans(policy, 1), nil))
	walk("POST "+prefix+"/policies/:id/versions", l.author, http.MethodPost, pp+"/versions",
		map[string]any{"intent": intent, "base_version_no": 1})
	walk("POST "+prefix+"/policies/:id/versions/:no/withdraw", l.author, http.MethodPost, pp+"/versions/2/withdraw",
		map[string]any{"reason": "walker"})
	code, resp := l.call(l.author, http.MethodPost, pp+"/versions", map[string]any{"intent": intent, "base_version_no": 2})
	l.must(code, resp, http.StatusCreated, "version 3")
	code, resp = l.call(l.author, http.MethodPost, pp+"/versions/3/propose", nil)
	l.must(code, resp, http.StatusOK, "propose 3")
	walk("POST "+prefix+"/policies/:id/versions/:no/reject", l.approver, http.MethodPost, pp+"/versions/3/reject",
		map[string]any{"reason": "walker"})
	walk("POST "+prefix+"/policies/:id/pause", l.author, http.MethodPost, pp+"/pause", map[string]any{"reason": "walker"})
	walk("POST "+prefix+"/policies/:id/resume", l.author, http.MethodPost, pp+"/resume", map[string]any{"reason": "walker"})
	walk("POST "+prefix+"/policies/:id/archive", l.author, http.MethodPost, pp+"/archive", map[string]any{"reason": "walker"})
	for _, r := range p3AuthoringRoutes(prefix) {
		if !walked[r] {
			t.Errorf("authoring route %s was not walked", r)
		}
	}
	vocab := map[string]bool{}
	for _, k := range services.GovEventVocabulary {
		vocab[k.Name] = true
	}
	var names []string
	l.db.Raw(`SELECT DISTINCT event FROM iga_gov_event WHERE workspace_id = ?`, l.ws).Scan(&names)
	for _, n := range names {
		if !vocab[n] {
			t.Errorf("event %s is not in the vocabulary", n)
		}
	}
}
