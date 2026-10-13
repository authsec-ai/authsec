package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/igagov"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// AS-108: IaC sources, IaC delivery and the export download are scoped to the
// token's (or the job's) workspace under row-level security. Workspace A
// cannot list, map onto or delete workspace B's IaC sources, cannot fetch
// B's export, and a job of A cannot deliver B's deployment.
func TestP3IaCTenancyCrossWorkspace(t *testing.T) {
	a := newP3iLab(t, "p3-iac-ten-a")
	b := newP3iLab(t, "p3-iac-ten-b")
	b.role("ModRole", "AROAMODROLE00001", p3iReport())
	b.publish()
	src := b.mapSource(iacpr.FormatTerraform, "stack", map[string]string{"stack/main.tf": `module "mod_role" {
  source    = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version   = "5.30.0"
  role_name = "ModRole"
}
`})
	b.grantWrite()
	policy, plans := b.propose(igagov.DeliveryIaCPR, "AROAMODROLE00001")
	ap := p3iPlan(t, plans, "apply")
	if ap["delivery"] != "export" {
		t.Fatalf("B's plan delivery %v", ap["delivery"])
	}
	b.approveAll(policy, 1)
	dep := b.deploy(policy, 1, "apply")
	if out := b.deliver(dep); out.State != "awaiting_apply" {
		t.Fatalf("B's export: %+v", out)
	}

	bSources := "/aws/connectors/" + b.a.conn.String() + "/iac-sources"

	// B's sources: not listed for A, not deletable by A, not mappable by A.
	if code, body := a.discCall(http.MethodGet, bSources, a.author, "governance:enforce", nil); code != http.StatusNotFound {
		t.Fatalf("A lists B's sources: %d %v", code, body)
	}
	if code, body := a.discCall(http.MethodDelete, bSources+"/"+src.String(), a.author, "governance:enforce", nil); code != http.StatusNotFound {
		t.Fatalf("A deletes B's source via B's connector: %d %v", code, body)
	}
	aSources := "/aws/connectors/" + a.a.conn.String() + "/iac-sources"
	if code, body := a.discCall(http.MethodDelete, aSources+"/"+src.String(), a.author, "governance:enforce", nil); code != http.StatusNotFound {
		t.Fatalf("A deletes B's source via its own connector: %d %v", code, body)
	}
	if code, body := a.discCall(http.MethodPost, aSources, a.author, "governance:enforce", map[string]any{"format": "terraform",
		"discovery_source_id": b.ds.String(), "repository": b.repo, "directory": "iam"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("A maps B's GitHub discovery source: %d %v", code, body)
	}
	if code, body := a.discCall(http.MethodGet, aSources, a.author, "governance:enforce", nil); code != http.StatusOK ||
		len(body["data"].([]any)) != 0 {
		t.Fatalf("A's own list: %d %v", code, body)
	}
	if n := p3sCount(t, b.db, `SELECT count(*) FROM iga_gov_iac_source WHERE workspace_id = ? AND id = ?`, b.ws, src); n != 1 {
		t.Fatalf("B's source after A's attempts: %d", n)
	}

	// B's export: A gets 404 for the version and for the download.
	code, body := b.call(b.author, http.MethodGet, "/policies/"+policy+"/versions/1/export", nil)
	ex := b.must(code, body, http.StatusOK, "B's export")
	planID := ""
	for _, x := range ex["plans"].([]any) {
		if x.(map[string]any)["kind"] == "apply" {
			planID, _ = x.(map[string]any)["plan_id"].(string)
		}
	}
	if planID == "" {
		t.Fatalf("B's export has no apply plan: %v", ex)
	}
	if code, body := a.call(a.author, http.MethodGet, "/policies/"+policy+"/versions/1/export", nil); code != http.StatusNotFound {
		t.Fatalf("A reads B's export: %d %v", code, body)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/iga/v1/policy/policies/"+policy+"/versions/1/export?download="+planID, nil)
	req.Header.Set("Authorization", "Bearer "+a.token(a.ws, a.author, p3aAllScopes))
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "aws_cli") {
		t.Fatalf("A downloads B's export: %d %s", w.Code, w.Body.String())
	}
	// B still downloads its own.
	req = httptest.NewRequest(http.MethodGet, "/api/iga/v1/policy/policies/"+policy+"/versions/1/export?download="+planID, nil)
	req.Header.Set("Authorization", "Bearer "+b.token(b.ws, b.author, p3aAllScopes))
	w = httptest.NewRecorder()
	b.eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("B downloads its export: %d %s", w.Code, w.Body.String())
	}

	// A job of A naming B's workspace or B's deployment does nothing.
	if _, err := a.delivery.ObserveApply(context.Background(), a.run(repositories.GovJobIaCSync, dep), b.ws, dep); err == nil {
		t.Fatal("A's job observed B's deployment under B's workspace")
	}
	var nf *services.GovError
	if _, err := a.delivery.ObserveApply(context.Background(), a.run(repositories.GovJobIaCSync, dep), a.ws, dep); err == nil ||
		!asGovNotFound(err, &nf) {
		t.Fatalf("A's job reached B's deployment: %v", err)
	}
	if d := b.dep(dep); d.State != "awaiting_apply" {
		t.Fatalf("B's deployment changed: %s", d.State)
	}
}

func asGovNotFound(err error, out **services.GovError) bool {
	ge, ok := err.(*services.GovError)
	if !ok {
		return false
	}
	*out = ge
	return ge.Status == http.StatusNotFound
}
