package platform

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/authsec-ai/authsec/pkg/agentstream"
)

// AgentStreamController handles WebSocket upgrades for the agent stream protocol.
type AgentStreamController struct {
	server *agentstream.Server
	logger *slog.Logger
}

// NewAgentStreamController creates a new stream controller.
func NewAgentStreamController(logger *slog.Logger) *AgentStreamController {
	handler := &agentstream.DefaultHandler{Logger: logger}
	return &AgentStreamController{
		server: agentstream.NewServer(handler),
		logger: logger,
	}
}

// Upgrade handles the WebSocket upgrade for agent streaming.
// GET /api/iga/v2/agent-stream
func (ctl *AgentStreamController) Upgrade(c *gin.Context) {
	wsID := c.GetString("workspace_id")
	collectorID := c.GetString("collector_id")
	if wsID == "" || collectorID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	principal := agentstream.Principal{
		WorkspaceID:  wsID,
		CollectorID:  collectorID,
		SPIFFEURI:    c.GetString("spiffe_uri"),
		IdentityMode: c.GetString("identity_mode"),
	}

	sess, err := ctl.server.AcceptSession(principal)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	ctl.logger.Info("agent stream session created",
		"session_id", sess.ID,
		"workspace_id", wsID,
		"collector_id", collectorID,
	)

	// In production, this would upgrade to a WebSocket using gorilla/websocket.
	// For now, return the session ID so the agent knows the connection is accepted.
	c.JSON(http.StatusOK, gin.H{
		"session_id":     sess.ID,
		"schema_version": agentstream.SchemaVersion,
		"message":        "WebSocket upgrade would occur here in production",
	})
}

// GetStatus returns the current stream server status.
// GET /api/iga/v2/agent-stream/status
func (ctl *AgentStreamController) GetStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"active_sessions": ctl.server.ActiveSessionCount(),
		"schema_version":  agentstream.SchemaVersion,
	})
}
