package integration

// T2.1 (SPEC-iga-phase2-graph.md §5.3, D-54): GET .../connectors/:id/regions
// and PATCH .../connectors/:id, through gin, over the REAL worker and
// projector. Gate: a region change applies to the next scan; an invalid region
// is 422 naming it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// GET .../regions lists the ENABLED regions with which are selected; a
// selected region the account no longer enables is listed enabled: false; a
// connector of another workspace, or a malformed id, is 404.
func TestP2S2RegionsListedWithSelection(t *testing.T) {
	l := newP2Lab(t, "p2-s2-regions-get", true)
	a := l.account(accountA, "us-east-1")
	fake := s2Regions("us-east-1", "eu-central-1", "me-central-1")
	fake.optedIn["me-central-1"] = true
	a.svc.WithRegionsAPI(fake)
	api := s2DiscoveryAPI(t, l, a.svc)

	code, body := api.do(http.MethodGet, "/aws/connectors/"+a.conn.String()+"/regions", nil)
	mustStatus(t, "GET regions", code, body, http.StatusOK)
	got := s2RegionRows(body)
	want := []string{
		"eu-central-1|opt-in-not-required|enabled|-",
		"me-central-1|opted-in|enabled|-",
		"us-east-1|opt-in-not-required|enabled|selected",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("regions = %v, want %v", got, want)
	}
	if fake.lastIn == nil || fake.lastIn.AllRegions == nil || *fake.lastIn.AllRegions {
		t.Fatalf("DescribeRegions must ask for ENABLED regions only (AllRegions=false), got %+v", fake.lastIn)
	}
	if dig(body, "success") != true || dig(body, "meta", "error") != nil ||
		digs(body, "meta", "integration") != refOf("cloud_connector", a.conn) {
		t.Fatalf("GET regions envelope = %v, want success, no error, the connector named", body)
	}
	// The stack version is stated as a fact: recorded at onboarding, current.
	if digs(body, "meta", "template", "deployed") != awsdiscovery.TemplateVersion ||
		dig(body, "meta", "template", "outdated") != false || dig(body, "meta", "template_outdated") != false {
		t.Fatalf("template facts = %v / %v", dig(body, "meta", "template"), dig(body, "meta", "template_outdated"))
	}

	// The account opts out of eu-central-1 after the connector selected it.
	l.db.Exec(`UPDATE cloud_connector SET attrs = jsonb_set(attrs, '{regions}', '["us-east-1","ap-south-2"]') WHERE id = ?`, a.conn)
	code, body = api.do(http.MethodGet, "/aws/connectors/"+a.conn.String()+"/regions", nil)
	mustStatus(t, "GET regions after opt-out", code, body, http.StatusOK)
	if rows := s2RegionRows(body); rows[0] != "ap-south-2|null|disabled|selected" {
		t.Fatalf("a selected region the account no longer enables = %v, want listed enabled:false, opt_in_status null", rows)
	}

	// Typed reference accepted; another type's reference, garbage, and another
	// workspace's connector are all 404 with no hint.
	if code, body := api.do(http.MethodGet, "/aws/connectors/cloud_connector:"+a.conn.String()+"/regions", nil); code != http.StatusOK {
		t.Fatalf("typed connector ref = %d %v", code, body)
	}
	for _, path := range []string{
		"/aws/connectors/workload:" + a.conn.String() + "/regions",
		"/aws/connectors/not-a-uuid/regions",
		"/aws/connectors/" + uuid.NewString() + "/regions",
	} {
		if code, body := api.do(http.MethodGet, path, nil); code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Fatalf("GET %s = %d %v, want 404 not_found", path, code, body)
		}
	}
	other := newWorkspace(t, l.db, "p2-s2-regions-foreign")
	if code, body := api.asWorkspace(other).do(http.MethodGet, "/aws/connectors/"+a.conn.String()+"/regions", nil); code != http.StatusNotFound || errCode(body) != "not_found" {
		t.Fatalf("another workspace's connector = %d %v, want 404 not_found", code, body)
	}
	// No workspace in the token: 401 in the structured envelope, and AWS is
	// never asked.
	calls := fake.calls
	api.asWorkspace(uuid.Nil)
	if code, body := api.do(http.MethodGet, "/aws/connectors/"+a.conn.String()+"/regions", nil); code != http.StatusUnauthorized || errCode(body) != "unauthenticated" {
		t.Fatalf("GET regions with no workspace = %d %v, want 401 unauthenticated", code, body)
	}
	if code, body := api.patchRegions(a.conn, "us-east-1"); code != http.StatusUnauthorized || errCode(body) != "unauthenticated" {
		t.Fatalf("PATCH with no workspace = %d %v, want 401 unauthenticated", code, body)
	}
	if fake.calls != calls {
		t.Fatalf("an unauthenticated request reached DescribeRegions")
	}
}

// PATCH validates against the ENABLED list and names every offender with 422
// invalid_region; nothing is written unless the whole selection is valid.
func TestP2S2RegionPatchNamesTheOffenders(t *testing.T) {
	l := newP2Lab(t, "p2-s2-regions-patch", true)
	a := l.account(accountA, "us-east-1")
	a.svc.WithRegionsAPI(s2Regions("us-east-1", "eu-central-1"))
	api := s2DiscoveryAPI(t, l, a.svc)

	// Well-formed, but not enabled in this account.
	code, body := api.patchRegions(a.conn, "eu-central-1", "ap-south-2", "me-central-1")
	mustStatus(t, "PATCH with regions not enabled", code, body, http.StatusUnprocessableEntity)
	if errCode(body) != "invalid_region" {
		t.Fatalf("code = %q, want invalid_region: %v", errCode(body), body)
	}
	if got := s2Strings(dig(body, "error", "regions")); !reflect.DeepEqual(got, []string{"ap-south-2", "me-central-1"}) {
		t.Fatalf("offenders = %v, want exactly [ap-south-2 me-central-1]", got)
	}
	if got := s2ConnectorRegions(t, l, a.conn); !reflect.DeepEqual(got, []string{"us-east-1"}) {
		t.Fatalf("a refused PATCH wrote regions %v", got)
	}

	// Not region codes at all: 422 naming them, before AWS is asked.
	code, body = api.patchRegions(a.conn, "us-east-1", "moon-1", "US_EAST")
	mustStatus(t, "PATCH with malformed codes", code, body, http.StatusUnprocessableEntity)
	if got := s2Strings(dig(body, "error", "regions")); !reflect.DeepEqual(got, []string{"moon-1", "us_east"}) {
		t.Fatalf("malformed offenders = %v", got)
	}

	// An EMPTY selection names no region, and is still 422 invalid_region
	// (D-90): it is no scan scope at all. Blank entries do not count.
	for _, raw := range []string{`{"regions": []}`, `{"regions": ["", "  "]}`} {
		code, body := api.do(http.MethodPatch, "/aws/connectors/"+a.conn.String(), json.RawMessage(raw))
		mustStatus(t, "PATCH "+raw, code, body, http.StatusUnprocessableEntity)
		if errCode(body) != "invalid_region" || dig(body, "error", "regions") == nil || len(digl(body, "error", "regions")) != 0 {
			t.Fatalf("PATCH %s = %v, want 422 invalid_region with regions: []", raw, body)
		}
	}

	// Not a region-selection body: 400 invalid_parameter. Only regions is
	// accepted, and an unknown field is refused, never ignored.
	tooMany := make([]string, 0, 33)
	for i := 1; i <= 33; i++ {
		tooMany = append(tooMany, fmt.Sprintf(`"us-east-%d"`, i))
	}
	for name, raw := range map[string]string{
		"missing":       `{}`,
		"null":          `{"regions": null}`,
		"not a list":    `{"regions": "us-east-1"}`,
		"unknown field": `{"regions": ["us-east-1"], "display_name": "x"}`,
		"not json":      `{"regions": `,
		"two objects":   `{"regions": ["us-east-1"]} {"regions": ["eu-central-1"]}`,
		"over the cap":  `{"regions": [` + strings.Join(tooMany, ",") + `]}`,
	} {
		code, body := api.do(http.MethodPatch, "/aws/connectors/"+a.conn.String(), json.RawMessage(raw))
		if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
			t.Fatalf("%s body = %d %v, want 400 invalid_parameter", name, code, body)
		}
	}
	if got := s2ConnectorRegions(t, l, a.conn); !reflect.DeepEqual(got, []string{"us-east-1"}) {
		t.Fatalf("a refused PATCH wrote regions %v", got)
	}

	// A valid change: normalized, de-duplicated, stored SORTED (D-90), and
	// returned.
	code, body = api.patchRegions(a.conn, "us-east-1", " EU-CENTRAL-1", "eu-central-1")
	mustStatus(t, "valid PATCH", code, body, http.StatusOK)
	if got := s2ConnectorRegions(t, l, a.conn); !reflect.DeepEqual(got, []string{"eu-central-1", "us-east-1"}) {
		t.Fatalf("stored regions = %v, want [eu-central-1 us-east-1]", got)
	}
	if got := s2Strings(dig(body, "meta", "previous_regions")); !reflect.DeepEqual(got, []string{"us-east-1"}) {
		t.Fatalf("previous_regions = %v", got)
	}
	if got := s2Strings(dig(body, "meta", "regions")); !reflect.DeepEqual(got, []string{"eu-central-1", "us-east-1"}) {
		t.Fatalf("meta.regions = %v", got)
	}
	if dig(body, "success") != true || digs(body, "data", "id") != a.conn.String() || dig(body, "data", "auth_ref") != nil {
		t.Fatalf("PATCH response = %v, want the connector (and never its secrets address)", body)
	}
	// Another workspace's connector is absent, not forbidden, and untouched.
	other := newWorkspace(t, l.db, "p2-s2-regions-patch-foreign")
	if code, body := api.asWorkspace(other).patchRegions(a.conn, "us-east-1"); code != http.StatusNotFound || errCode(body) != "not_found" {
		t.Fatalf("PATCH of another workspace's connector = %d %v, want 404 not_found", code, body)
	}
	api.asWorkspace(l.ws)
	if got := s2ConnectorRegions(t, l, a.conn); !reflect.DeepEqual(got, []string{"eu-central-1", "us-east-1"}) {
		t.Fatalf("a foreign PATCH changed the regions to %v", got)
	}

	// A revoked connection cannot be reconfigured.
	l.db.Exec(`UPDATE cloud_connector SET status = 'revoked', auth_ref = '' WHERE id = ?`, a.conn)
	code, body = api.patchRegions(a.conn, "us-east-1")
	if code != http.StatusConflict || errCode(body) != "connector_revoked" {
		t.Fatalf("PATCH on a revoked connector = %d %v, want 409 connector_revoked", code, body)
	}
}

// A DENIED ec2:DescribeRegions (D-90) is stated, not mis-mapped: GET still
// answers 200 with the SELECTED regions, enabled: null (not known), and
// meta.error naming the call and the code AWS returned -- never the onboarding
// mapping's 400 "the role could not be assumed; check the trust policy and the
// ExternalId", which sends the customer the wrong way. PATCH, which cannot
// validate, is 422 regions_unavailable and writes nothing.
func TestP2S2DeniedDescribeRegionsIsAClearError(t *testing.T) {
	l := newP2Lab(t, "p2-s2-regions-denied", true)
	a := l.account(accountA, "us-east-1", "eu-central-1")
	fake := s2Regions()
	fake.err = &smithy.OperationError{ServiceID: "EC2", OperationName: "DescribeRegions",
		Err: &smithy.GenericAPIError{Code: "UnauthorizedOperation", Message: "You are not authorized to perform this operation."}}
	a.svc.WithRegionsAPI(fake)
	api := s2DiscoveryAPI(t, l, a.svc)
	// The stack this account runs predates the one granting DescribeRegions
	// explicitly: stated as a fact beside the failure, never as its cause.
	l.db.Exec(`UPDATE cloud_connector SET attrs = jsonb_set(attrs, '{template_version}', '"2026-09-18"') WHERE id = ?`, a.conn)

	code, body := api.do(http.MethodGet, "/aws/connectors/"+a.conn.String()+"/regions", nil)
	mustStatus(t, "GET regions with DescribeRegions denied", code, body, http.StatusOK)
	if got := s2RegionRows(body); !reflect.DeepEqual(got, []string{
		"eu-central-1|null|unknown|selected", "us-east-1|null|unknown|selected",
	}) {
		t.Fatalf("regions when AWS refused = %v, want the selection with enabled: null", got)
	}
	failure := dig(body, "meta", "error")
	if digs(failure, "code") != "aws_access_denied" || digs(failure, "api") != "ec2:DescribeRegions" ||
		digs(failure, "error_code") != "UnauthorizedOperation" || digs(failure, "fault") != "customer_account" {
		t.Fatalf("meta.error = %v, want the failed call and AWS's code", failure)
	}
	if msg := digs(failure, "message"); strings.Contains(msg, "could not be assumed") ||
		strings.Contains(strings.ToLower(msg), "externalid") || !strings.Contains(msg, "not authorized to perform") {
		t.Fatalf("a denied DescribeRegions reads as an assume failure, or lost AWS's words: %q", msg)
	}
	if dig(body, "meta", "template_outdated") != true || digs(body, "meta", "template", "deployed") != "2026-09-18" ||
		digs(body, "meta", "template", "current") != awsdiscovery.TemplateVersion {
		t.Fatalf("template facts = %v / %v", dig(body, "meta", "template"), dig(body, "meta", "template_outdated"))
	}
	// Never a guessed permission: nothing names what to grant.
	for k := range failure.(map[string]any) {
		if strings.Contains(k, "permission") || strings.Contains(k, "missing") || strings.Contains(k, "grant") {
			t.Fatalf("meta.error carries %q: a guessed permission", k)
		}
	}

	code, body = api.patchRegions(a.conn, "us-east-1")
	mustStatus(t, "PATCH with DescribeRegions denied", code, body, http.StatusUnprocessableEntity)
	if errCode(body) != "regions_unavailable" || digs(body, "error", "api") != "ec2:DescribeRegions" ||
		digs(body, "error", "error_code") != "UnauthorizedOperation" || digs(body, "error", "failure") != "aws_access_denied" {
		t.Fatalf("PATCH when the enabled list cannot be read = %v, want 422 regions_unavailable naming the call", body)
	}
	if got := s2ConnectorRegions(t, l, a.conn); !reflect.DeepEqual(got, []string{"us-east-1", "eu-central-1"}) {
		t.Fatalf("a PATCH that could not validate wrote %v", got)
	}

	// Throttled: the same shape, on AWS's side.
	fake.err = &smithy.OperationError{ServiceID: "EC2", OperationName: "DescribeRegions",
		Err: &smithy.GenericAPIError{Code: "RequestLimitExceeded", Message: "Request limit exceeded."}}
	code, body = api.do(http.MethodGet, "/aws/connectors/"+a.conn.String()+"/regions", nil)
	mustStatus(t, "GET regions throttled", code, body, http.StatusOK)
	if digs(body, "meta", "error", "code") != "aws_throttled" || digs(body, "meta", "error", "fault") != "aws" ||
		digs(body, "meta", "error", "error_code") != "RequestLimitExceeded" {
		t.Fatalf("throttled meta.error = %v", dig(body, "meta", "error"))
	}
	if code, body := api.patchRegions(a.conn, "us-east-1"); code != http.StatusUnprocessableEntity || errCode(body) != "regions_unavailable" {
		t.Fatalf("PATCH throttled = %d %v, want 422 regions_unavailable", code, body)
	}

	// An AuthSec-side failure never reaches AWS and is ours: 500 -- never the
	// 200-with-error (which would blame the customer's account) nor a 4xx.
	// This verifier cannot build a session, so the service fails before any
	// AWS call.
	plain := s2DiscoveryAPI(t, l, services.NewAWSOnboardingService(l.db, newMemVault()).WithVerifier(&stubVerifier{}))
	code, body = plain.do(http.MethodGet, "/aws/connectors/"+a.conn.String()+"/regions", nil)
	if code != http.StatusInternalServerError || errCode(body) != "internal" || digs(body, "error", "fault") != "authsec" {
		t.Fatalf("GET regions with no AWS session possible = %d %v, want 500 internal", code, body)
	}
	if code, body := plain.patchRegions(a.conn, "us-east-1"); code != http.StatusInternalServerError {
		t.Fatalf("PATCH with no AWS session possible = %d %v, want 500", code, body)
	}
}

// THE GATE (§6.2 T2.1): a region change applies to the NEXT scan, not the one
// in flight. The PATCH lands inside the permission scan -- after the IAM scan
// and before the workload scan, which used to re-read the connector -- and the
// run must still read compute only in the regions it was claimed with.
func TestP2S2RegionChangeAppliesFromTheNextScan(t *testing.T) {
	l := newP2Lab(t, "p2-s2-regions-next", true)
	a := l.account(accountA, "us-east-1")
	role := a.role("fn-role", "AROAS2REGIONNEXTXXXX")
	a.lambda("us-east-1", "east-fn", role)
	a.lambda("eu-central-1", "central-fn", role)
	a.svc.WithRegionsAPI(s2Regions("us-east-1", "eu-central-1"))
	api := s2DiscoveryAPI(t, l, a.svc)

	var patched bool
	var mu sync.Mutex
	run := s2ScanWith(l, a, "s2-worker-inflight", func(_ *services.AWSIAMScanner, p *services.AWSPermissionScanner, _ *services.AWSWorkloadScanner) {
		p.WithEKSAPI(&s2DuringEKS{fakeEKS: newFakeEKS(), during: func() {
			code, body := api.patchRegions(a.conn, "us-east-1", "eu-central-1")
			mustStatus(t, "PATCH mid-run", code, body, http.StatusOK)
			mu.Lock()
			patched = true
			mu.Unlock()
		}})
	})
	if !patched {
		t.Fatal("setup: the PATCH never ran inside the scan")
	}
	if run.Status != models.CloudScanRunPublished {
		t.Fatalf("in-flight run = %s (%s), want published", run.Status, run.LastError)
	}
	cov := s2Coverage(run).Surfaces
	if _, ok := cov["lambda:eu-central-1"]; ok {
		t.Fatalf("the run in flight read eu-central-1, selected AFTER it was claimed: %v", cov["lambda:eu-central-1"])
	}
	if cov["compute:eu-central-1"].State != models.CloudCoverageNotSelected {
		t.Fatalf("the in-flight run's eu-central-1 = %+v, want not_selected (its claimed scope)", cov["compute:eu-central-1"])
	}
	if cov["lambda:us-east-1"].State != models.CloudCoverageReached {
		t.Fatalf("lambda:us-east-1 = %+v, want reached", cov["lambda:us-east-1"])
	}
	if n := l.count(`SELECT count(*) FROM cloud_workload WHERE workspace_id = ? AND region = 'eu-central-1'`, l.ws); n != 0 {
		t.Fatalf("the in-flight run wrote %d eu-central-1 workloads", n)
	}
	if got := s2ConnectorRegions(t, l, a.conn); !reflect.DeepEqual(got, []string{"eu-central-1", "us-east-1"}) {
		t.Fatalf("the PATCH itself did not persist: %v", got)
	}
	l.project("s2-projector-inflight")

	// The NEXT scan reads the new selection.
	next := s2ScanWith(l, a, "s2-worker-next", nil)
	cov = s2Coverage(next).Surfaces
	if cov["lambda:eu-central-1"].State != models.CloudCoverageReached {
		t.Fatalf("the next scan's lambda:eu-central-1 = %+v, want reached", cov["lambda:eu-central-1"])
	}
	if _, ok := cov["compute:eu-central-1"]; ok {
		t.Fatalf("the next scan still reports eu-central-1 not selected")
	}
	if n := l.count(`SELECT count(*) FROM cloud_workload WHERE workspace_id = ? AND region = 'eu-central-1'`, l.ws); n != 1 {
		t.Fatalf("eu-central-1 workloads after the next scan = %d, want 1", n)
	}
	l.project("s2-projector-next")
}

// A verification must not undo a region change that commits while AWS is
// answering: it used to write back the whole attrs blob it read BEFORE the
// probe.
func TestP2S2VerifyDoesNotUndoARegionChange(t *testing.T) {
	l := newP2Lab(t, "p2-s2-verify-race", true)
	v := &s2DuringVerifier{identity: &awsdiscovery.Identity{
		AccountID: accountA,
		ARN:       "arn:aws:sts::" + accountA + ":assumed-role/AuthSecCloudDiscovery/authsec-discovery-s2",
		UserID:    "AROAS2:authsec-discovery-s2",
	}}
	svc, _ := newOnboarding(l.db, v)
	svc.WithRegionsAPI(s2Regions("us-east-1", "eu-central-1"))
	c, _, err := svc.Onboard(context.Background(), l.ws, services.AWSOnboardInput{
		RoleARN: "arn:aws:iam::" + accountA + ":role/AuthSecCloudDiscovery", ExternalID: mustMint(t, l.ws),
		Regions: []string{"us-east-1"}, DisplayName: "race",
	}, "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	v.during = func() {
		if _, _, err := svc.UpdateRegions(context.Background(), l.ws, c.ID, []string{"us-east-1", "eu-central-1"}); err != nil {
			t.Errorf("region change during the probe: %v", err)
		}
	}
	verified, err := svc.VerifyConnector(context.Background(), l.ws, c.ID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := verified.AWSAttrs().Regions; !reflect.DeepEqual(got, []string{"eu-central-1", "us-east-1"}) {
		t.Fatalf("regions after a verify that raced a PATCH = %v: the verify wrote back what it read before the probe", got)
	}
	if verified.AWSAttrs().CallerARN != v.identity.ARN {
		t.Fatalf("caller_arn = %q, want the verified identity", verified.AWSAttrs().CallerARN)
	}
	if verified.Status != models.CloudConnectorActive {
		t.Fatalf("status = %s after a successful verify", verified.Status)
	}
}

// A region outside the built-in list can now be selected (any ENABLED one);
// deselecting it must still leave its earlier results kept and marked STALE
// (§2.14.13), not "current" forever.
func TestP2S2DeselectedRegionIsKeptStale(t *testing.T) {
	l := newP2Lab(t, "p2-s2-deselect", true)
	a := l.account(accountA, "us-east-1", "ap-south-2") // not in the built-in 17
	role := a.role("fn-role", "AROAS2DESELECTXXXXXX")
	a.lambda("ap-south-2", "hyderabad-fn", role)
	a.svc.WithRegionsAPI(s2Regions("us-east-1", "ap-south-2"))
	api := s2DiscoveryAPI(t, l, a.svc)
	l.scanAndProject(a)
	if st := s2EdgeState(l, "hyderabad-fn"); st != models.RelCurrent {
		t.Fatalf("setup: hyderabad-fn executes_as = %q, want current", st)
	}

	code, body := api.patchRegions(a.conn, "us-east-1")
	mustStatus(t, "deselect ap-south-2", code, body, http.StatusOK)
	run := l.scanAndProject(a)

	if st := s2Coverage(run).Surfaces["compute:ap-south-2"].State; st != models.CloudCoverageNotSelected {
		t.Fatalf("compute:ap-south-2 after deselection = %q, want not_selected", st)
	}
	if st := s2EdgeState(l, "hyderabad-fn"); st != models.RelStale {
		t.Fatalf("hyderabad-fn executes_as after deselection = %q, want stale (kept, not confirmed)", st)
	}
	var life string
	l.db.Raw(`SELECT lifecycle FROM iga_workload WHERE workspace_id = ? AND display_name = 'hyderabad-fn'`, l.ws).Scan(&life)
	if life != models.IGALifecycleActive {
		t.Fatalf("hyderabad-fn = %q after deselection, want active (kept)", life)
	}
}

/* --------------------------------- helpers -------------------------------- */

// s2DuringVerifier is a Verifier that runs `during` inside Verify -- while
// "AWS is answering".
type s2DuringVerifier struct {
	identity *awsdiscovery.Identity
	during   func()
}

func (v *s2DuringVerifier) Verify(_ context.Context, _ awsdiscovery.AssumeRequest) (*awsdiscovery.Identity, error) {
	if v.during != nil {
		v.during()
	}
	return v.identity, nil
}

// s2RegionRows renders GET .../regions rows as name|opt_in|enabled|selected.
func s2RegionRows(body map[string]any) []string {
	var out []string
	for _, r := range digl(body, "data") {
		opt := digs(r, "opt_in_status")
		if dig(r, "opt_in_status") == nil {
			opt = "null"
		}
		en, sel := "disabled", "-"
		switch dig(r, "enabled") {
		case true:
			en = "enabled"
		case nil:
			en = "unknown"
		}
		if dig(r, "selected") == true {
			sel = "selected"
		}
		out = append(out, digs(r, "name")+"|"+opt+"|"+en+"|"+sel)
	}
	return out
}

func s2Strings(v any) []string {
	var out []string
	for _, x := range digl(v) {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// s2EdgeState is the state of a workload's executes_as relationship.
func s2EdgeState(l *p2Lab, workload string) string {
	var st string
	l.db.Raw(`SELECT r.state FROM iga_relationship r
	            JOIN iga_workload w ON w.id = r.source_workload_id
	           WHERE r.workspace_id = ? AND r.relationship_type = 'executes_as' AND w.display_name = ?`,
		l.ws, workload).Scan(&st)
	return st
}
