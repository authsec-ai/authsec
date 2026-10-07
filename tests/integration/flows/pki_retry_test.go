//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/clients/icp"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/services"
)

// A successful PKI retry marks the workspace active with its mount and CA.
// The update named a workspace_id column the registry does not have, so it
// failed after every successful provisioning and the workspace was
// re-provisioned on every pass.
func Test_PKIRetryWorker_MarksWorkspaceActive(t *testing.T) {
	testsupport.Get(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, emailSafeNonce())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	mustExec(t, `UPDATE workspaces SET status = 'pki_provisioning_failed', vault_mount = NULL WHERE id = $1`, ws.WorkspaceID)
	// Other workspaces seeded by earlier tests must not be retried here.
	mustExec(t, `UPDATE workspaces SET status = 'active' WHERE status = 'pki_provisioning_failed' AND id <> $1`, ws.WorkspaceID)

	icpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/admin/pki/provision/"+ws.WorkspaceID.String()) {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"pki_mount": "pki-test", "ca_cert": "CA-PEM"})
	}))
	defer icpSrv.Close()

	icpSvc := services.NewICPProvisioningService(icp.NewClient(icpSrv.URL, "t"))
	w := services.NewPKIRetryWorker(&database.DBConnection{DB: config.GetDatabase().DB}, icpSvc, time.Hour)
	w.RunOnce()

	assertCount(t, 1, "workspaces", "id = ? AND status = 'active' AND vault_mount = 'pki-test' AND ca_cert = 'CA-PEM'", ws.WorkspaceID)
}
