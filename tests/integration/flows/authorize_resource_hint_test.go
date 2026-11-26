//go:build integration

package flows

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// AS-070: when /oauth/authorize can't infer the resource, the error names no
// resource servers (it used to list every active one, across workspaces).
func Test_Authorize_AmbiguousResourceListsNothing(t *testing.T) {
	env := testsupport.Get(t)
	a, b := TwoTenants(t)
	n := emailSafeNonce()
	rs1, err := AddResourceServer(config.DB, a.WS, "https://one-"+n+".example.com", n+"1")
	if err != nil {
		t.Fatal(err)
	}
	rs2, err := AddResourceServer(config.DB, a.WS, "https://two-"+n+".example.com", n+"2")
	if err != nil {
		t.Fatal(err)
	}
	rsB, err := AddResourceServer(config.DB, b.WS, "https://other-"+n+".example.com", n+"b")
	if err != nil {
		t.Fatal(err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, a.WS, rs1, n)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, `INSERT INTO resource_server_client_registrations (id, resource_server_id, oauth_client_id,
			workspace_id, status, registration_type)
		VALUES (?, ?, ?, ?, 'approved', 'prereg')`, uuid.New(), rs2.RSID, sa.ClientID, a.WS.WorkspaceID)

	q := url.Values{
		"client_id":             {sa.ClientIDString},
		"response_type":         {"code"},
		"redirect_uri":          {"https://app.example.com/cb"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}
	w := env.Do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, "")
	out := w.Body.String() + w.Header().Get("Location")
	for _, uri := range []string{rs1.ResourceURI, rs2.ResourceURI, rsB.ResourceURI} {
		if strings.Contains(out, uri) || strings.Contains(out, url.QueryEscape(uri)) {
			t.Fatalf("authorize error names resource %s: %d %s", uri, w.Code, out)
		}
	}
	if !strings.Contains(out, "resource") {
		t.Fatalf("expected a resource-required error, got %d %s", w.Code, out)
	}
}
