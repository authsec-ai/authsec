package integration

// The Phase 2 discovery routes, field by field (SPEC-iga-phase2-graph.md §5.3
// "Integration, scan and pipeline"; D-54, D-90, D-91): GET
// .../connectors/:id/regions, PATCH .../connectors/:id, GET
// .../connectors/:id/scan-runs, and the projection GET .../scan-runs/:id
// gained. They answer in the discovery routes' own envelope ({success, data,
// meta}) and are not revision-bound (D-91). The errors their HANDLERS raise
// on the three new routes (400, 401 for a token with no workspace, 404, 422)
// are the §5.2 envelope. The 401 and 403 of the discovery group's shared
// authentication and permission middleware are NOT: they keep the shared
// bodies, as every other /authsec/discovery route does (D-9 scopes the §5.2
// denial envelope to the graph routes; D-101) -- so this test drives the
// handlers and claims nothing about the middleware's bodies. Built over the
// REAL worker and projector.

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
)

var (
	// One region of GET .../regions (D-54): enabled null only when AWS could
	// not be asked (D-90).
	contractRegion = contractObj(
		contractReq("name", contractNonEmpty),
		contractReq("opt_in_status", contractNullable(contractNonEmpty)),
		contractReq("enabled", contractNullable(contractBool)),
		contractReq("selected", contractBool),
	)

	// The stack version facts (D-72): recorded, current, outdated.
	contractTemplate = contractObj(
		contractReq("deployed", contractNullable(contractNonEmpty)),
		contractReq("current", contractNonEmpty),
		contractReq("outdated", contractNullable(contractBool)),
	)

	// A run's projection (§5.3 "gains projection: { status, rev }"; D-59,
	// D-91): null when the run has no job.
	contractRunProjection = contractNullable(contractObj(
		contractReq("status", contractEnum("pending", "running", "complete", "failed", "abandoned")),
		contractReq("rev", contractNullable(contractInt)),
		contractReq("attempts", contractInt),
		contractReq("retrying", contractBool),
		contractReq("last_error", contractNullable(contractStr)),
	))

	// One run of GET .../scan-runs (D-91; D-55 queued_at).
	contractRunItem = contractObj(
		contractReq("ref", contractRunRef),
		contractReq("id", contractNonEmpty),
		contractReq("integration", contractRef("cloud_connector")),
		contractReq("status", contractEnum("queued", "running", "published", "failed", "abandoned")),
		contractReq("trigger", contractNonEmpty),
		contractReq("attempts", contractInt),
		contractReq("generation", contractInt),
		contractReq("queued_at", contractTime),
		contractReq("started_at", contractNullable(contractTime)),
		contractReq("published_at", contractNullable(contractTime)),
		contractReq("finished_at", contractNullable(contractTime)),
		contractReq("updated_at", contractTime),
		contractReq("last_error", contractNullable(contractStr)),
		contractReq("coverage", contractNullable(contractObj(
			contractReq("status", contractNonEmpty),
			contractReq("counts", contractMap(contractInt)),
			contractReq("not_reached", contractArr(contractObj(
				contractReq("surface", contractNonEmpty),
				contractReq("state", contractSurfaceState),
				contractReq("api", contractNullable(contractNonEmpty)),
				contractReq("error_code", contractNullable(contractNonEmpty)),
			))),
		))),
		contractReq("projection", contractRunProjection),
	)

	// as_of is when the route answered: live state (D-82, D-91).
	contractAsOf = contractReq("as_of", contractTime)
)

func TestP2ContractDiscoveryRoutes(t *testing.T) {
	l := newP2Lab(t, "p2-contract-discovery", true)
	a := oneLambda(l)
	fake := s2Regions("us-east-1", "eu-central-1")
	fake.optedIn["eu-central-1"] = true
	a.svc.WithRegionsAPI(fake)
	d := s2DiscoveryAPI(t, l, a.svc)
	conn := "/aws/connectors/" + a.conn.String()

	published := l.scanAndProject(a)
	time.Sleep(5 * time.Millisecond)
	failed, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := l.runs.ClaimForPipeline("contract-failing-worker", time.Minute, time.Now())
	if err != nil || claimed == nil || claimed.ID != failed.ID {
		t.Fatalf("claim the run to fail: %v %v", claimed, err)
	}
	if err := l.runs.Fail(failed.ID, "contract-failing-worker", claimed.LeaseVersion, "iam scan: connection reset"); err != nil {
		t.Fatal(err)
	}

	// GET .../regions.
	code, body := d.do(http.MethodGet, conn+"/regions", nil)
	mustStatus(t, "GET regions", code, body, http.StatusOK)
	contractCheck(t, "GET regions", body, contractObj(
		contractReq("success", contractConst(true)),
		contractReq("data", contractArrMin(2, contractRegion)),
		contractReq("meta", contractObj(contractAsOf,
			contractReq("integration", contractConst(refOf("cloud_connector", a.conn))),
			contractReq("source", contractConst("ec2:DescribeRegions")),
			contractReq("error", contractNull),
			// The stack version recorded at onboarding and this build's, as
			// facts (D-72).
			contractReq("template", contractAll(contractTemplate, contractConst(map[string]any{
				"deployed": awsdiscovery.TemplateVersion, "current": awsdiscovery.TemplateVersion, "outdated": false,
			}))),
			contractReq("template_outdated", contractConst(false)),
			contractReq("note", contractNonEmpty),
		)),
	))
	if r := contractByName(digl(body, "data"), "name"); digs(r["eu-central-1"], "opt_in_status") != "opted-in" ||
		dig(r["eu-central-1"], "selected") != false || dig(r["us-east-1"], "selected") != true || dig(r["us-east-1"], "enabled") != true {
		t.Errorf("regions = %s", contractJSON(body["data"]))
	}

	// PATCH .../connectors/:id: 200, then 422 invalid_region naming the
	// offenders (D-54), then 400 for a field it does not accept (D-90).
	code, body = d.patchRegions(a.conn, "us-east-1", "eu-central-1")
	mustStatus(t, "PATCH", code, body, http.StatusOK)
	contractCheck(t, "PATCH", body, contractObj(
		contractReq("success", contractConst(true)),
		contractReq("message", contractNonEmpty),
		contractReq("data", contractFunc(func(path string, v any, errs *[]string) {
			if digs(v, "id") != a.conn.String() {
				contractFail(errs, path, "want the connector, got %s", contractJSON(v))
			}
		})),
		contractReq("meta", contractObj(contractAsOf,
			contractReq("regions", contractConst([]any{"eu-central-1", "us-east-1"})),
			contractReq("previous_regions", contractConst([]any{"us-east-1"})),
			contractReq("applies", contractNonEmpty),
		)),
	))
	code, body = d.patchRegions(a.conn, "us-east-1", "ap-south-2")
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("PATCH a region not enabled = %d %s", code, contractJSON(body))
	}
	contractCheck(t, "PATCH 422", body, contractError("invalid_region",
		contractReq("regions", contractConst([]any{"ap-south-2"})), contractReq("reason", contractNonEmpty)))
	code, body = d.do(http.MethodPatch, conn, map[string]any{"regions": []string{"us-east-1"}, "display_name": "x"})
	if code != http.StatusBadRequest {
		t.Fatalf("PATCH an unknown field = %d %s", code, contractJSON(body))
	}
	contractCheck(t, "PATCH 400", body, contractError("invalid_parameter", contractReq("parameter", contractConst("body"))))

	// GET .../scan-runs: newest first, cursor-paged (D-91).
	code, body = d.do(http.MethodGet, conn+"/scan-runs?limit=1", nil)
	mustStatus(t, "GET scan-runs", code, body, http.StatusOK)
	historyMeta := func(limit int64, next contractShape) contractShape {
		return contractObj(contractAsOf,
			contractReq("integration", contractConst(refOf("cloud_connector", a.conn))),
			contractReq("sort", contractConst("-requested_at")),
			contractReq("limit", contractConst(limit)),
			contractReq("next_cursor", next),
			contractReq("note", contractNonEmpty),
		)
	}
	contractCheck(t, "GET scan-runs", body, contractObj(
		contractReq("success", contractConst(true)),
		contractReq("data", contractArrMin(1, contractRunItem)),
		contractReq("meta", historyMeta(1, contractNonEmpty)),
	))
	first := dig(body, "data", 0)
	if digs(first, "ref") != refOf("cloud_scan_run", failed.ID) || digs(first, "status") != "failed" ||
		digs(first, "last_error") != "iam scan: connection reset" || dig(first, "finished_at") == nil || dig(first, "projection") != nil {
		t.Errorf("newest run = %s, want the failed one, finished, with its error and no projection", contractJSON(first))
	}
	code, body = d.do(http.MethodGet, conn+"/scan-runs?limit=1&cursor="+digs(body, "meta", "next_cursor"), nil)
	mustStatus(t, "GET scan-runs page 2", code, body, http.StatusOK)
	contractCheck(t, "GET scan-runs page 2", body, contractObj(
		contractReq("success", contractConst(true)),
		contractReq("data", contractArrMin(1, contractRunItem)),
		contractReq("meta", historyMeta(1, contractNullable(contractNonEmpty))),
	))
	pub := dig(body, "data", 0)
	if digs(pub, "ref") != refOf("cloud_scan_run", published.ID) || digs(pub, "status") != "published" ||
		num(pub, "projection", "rev") != 1 || digs(pub, "projection", "status") != "complete" ||
		digs(pub, "finished_at") != digs(pub, "published_at") || dig(pub, "coverage") == nil {
		t.Errorf("published run = %s, want projected at rev 1, finished when published", contractJSON(pub))
	}
	code, body = d.do(http.MethodGet, conn+"/scan-runs?contract_bogus=1", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("scan-runs with an unknown parameter = %d", code)
	}
	contractCheck(t, "scan-runs 400", body, contractError("invalid_parameter", contractReq("parameter", contractConst("contract_bogus"))))
	code, body = d.do(http.MethodGet, conn+"/scan-runs?cursor=garbage", nil)
	if code != http.StatusBadRequest {
		t.Fatalf("scan-runs with a garbage cursor = %d", code)
	}
	contractCheck(t, "scan-runs cursor", body, contractError("cursor_invalid"))

	// GET .../scan-runs/:id gains projection {status, rev, ...}.
	code, body = d.do(http.MethodGet, "/aws/scan-runs/"+published.ID.String(), nil)
	mustStatus(t, "GET scan-run", code, body, http.StatusOK)
	contractCheck(t, "GET scan-run projection", dig(body, "data", "projection"), contractRunProjection)
	if num(body, "data", "projection", "rev") != 1 || digs(body, "data", "id") != published.ID.String() {
		t.Errorf("scan run = %s, want its projection at rev 1", contractJSON(body["data"]))
	}

	// The §5.2 envelope for these handlers' errors: 404 with no hint, and the
	// handler's own 401 for a token that names no workspace.
	code, body = d.do(http.MethodGet, "/aws/connectors/workload:"+a.conn.String()+"/regions", nil)
	if code != http.StatusNotFound {
		t.Fatalf("another type's ref = %d", code)
	}
	contractCheck(t, "regions 404", body, contractError("not_found"))
	d.asWorkspace(uuid.Nil)
	code, body = d.do(http.MethodGet, conn+"/scan-runs", nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("no workspace = %d", code)
	}
	contractCheck(t, "scan-runs 401", body, contractError("unauthenticated"))
}
