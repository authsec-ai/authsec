package platform

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Phase 2 connector routes (§5.3 Integration, scan and pipeline; T2.1, T2.2):
// GET /aws/connectors/:id/regions, PATCH /aws/connectors/:id,
// GET /aws/connectors/:id/scan-runs.
//
// STUB: every handler answers 501 until its task lands. Replace this file whole.

func (ctl *CloudAWSController) GetConnectorRegions(c *gin.Context)   { awsNotYet(c) }
func (ctl *CloudAWSController) UpdateConnector(c *gin.Context)       { awsNotYet(c) }
func (ctl *CloudAWSController) ListConnectorScanRuns(c *gin.Context) { awsNotYet(c) }

func awsNotYet(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}
