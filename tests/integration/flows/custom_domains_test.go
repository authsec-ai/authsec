//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
)

// Intern report (Custom Domains): invalid names were accepted and a failed
// DNS check said only "verification failed". Another workspace's domain is a
// 404 (it was a 403).
func Test_CustomDomains_ValidateAndExplain(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	base := func(tn *Tenant) string {
		return "/authsec/uflow/admin/tenants/" + tn.WS.WorkspaceID.String() + "/domains"
	}

	for _, bad := range []string{"bad domain!!", "example", "10.0.0.1", "-x.example.com"} {
		w := env.Do("POST", base(a), map[string]interface{}{"domain": bad}, a.AdminToken)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid domain") {
			t.Errorf("create %q: %d %s, want 400 invalid domain", bad, w.Code, w.Body.String())
		}
	}

	w := env.Do("POST", base(a), map[string]interface{}{"domain": "login-" + emailSafeNonce() + ".invalid"}, a.AdminToken)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct {
		Domain struct {
			ID string `json:"id"`
		} `json:"domain"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.Domain.ID == "" {
		t.Fatalf("create response: %v %s", err, w.Body.String())
	}

	// .invalid never resolves (RFC 6761): the record is reported missing.
	t.Setenv("SKIP_DNS_VERIFICATION", "")
	w = env.Do("POST", base(a)+"/"+created.Domain.ID+"/verify", nil, a.AdminToken)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
	var failed struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &failed)
	if failed.Error == "verification failed" || !strings.Contains(failed.Error, "_authsec-challenge.") {
		t.Errorf("verify failure does not say why: %q", failed.Error)
	}

	assertCrossTenant404(t, "POST", base(b)+"/"+created.Domain.ID+"/verify", nil, b.AdminToken)
}
