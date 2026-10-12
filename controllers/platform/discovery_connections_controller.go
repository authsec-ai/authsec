package platform

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// DiscoveryConnectionsController serves the one connections read the console's
// Connections screen is built on (SPEC-console-revamp.md B3).
type DiscoveryConnectionsController struct {
	reader *igaread.Reader
}

// NewDiscoveryConnectionsController reads through internal/igaread, which owns
// the snapshot and the deadline. The read does not page, so it needs no cursor
// key; and it is not a graph read, so it is not behind the graph projection
// gate: whether a connection exists and what state it is in does not depend on
// the projection switch.
func NewDiscoveryConnectionsController(db *gorm.DB) *DiscoveryConnectionsController {
	return &DiscoveryConnectionsController{reader: igaread.NewReader(db, nil)}
}

// ListConnections handles GET /authsec/discovery/connections: every AWS, GCP,
// Kubernetes and GitHub connection of the caller's workspace, in one shape.
// Read-only; the workspace is the token's and nothing in the request can
// change it. It takes no parameters.
func (ctl *DiscoveryConnectionsController) ListConnections(c *gin.Context) {
	_, ok := tokenWorkspace(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in token"})
		return
	}
	body, err := ctl.reader.ListConnections(c.Request.Context())
	if err != nil {
		e := igaread.AsError(err)
		if e.Status >= 500 && e.Status != http.StatusServiceUnavailable {
			log.Printf("[connections] %s: %v", c.FullPath(), e)
		}
		c.JSON(e.Status, gin.H{"error": e.Message})
		return
	}
	c.JSON(http.StatusOK, body)
}

// CanAdminister handles GET /authsec/discovery/connections/can-administer. It
// is mounted behind the same discovery:admin middleware as the administrative
// connection routes, so reaching this handler IS the answer: the server's own
// decision about this caller, never a copy of it. The console asks once so it
// can show a read-only reader no Scan, Verify, Edit scope or Revoke control at
// all; a 403 here is the other answer. The routes themselves enforce either way.
func (ctl *DiscoveryConnectionsController) CanAdminister(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"can_administer": true})
}
