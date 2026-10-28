package platform

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CapabilityController serves per-workload enforcement capability metadata.
// A capability describes what a workload's collector can enforce at runtime:
// which control kinds are available, what adapter backs each one, and the
// set of supported effects and enforcement modes.
type CapabilityController struct{}

// NewCapabilityController constructs the controller.
func NewCapabilityController() *CapabilityController {
	return &CapabilityController{}
}

// WorkloadCapability describes what a workload's collector can enforce.
type WorkloadCapability struct {
	WorkloadID       string              `json:"workload_id"`
	CollectorID      string              `json:"collector_id,omitempty"`
	SupportedEffects []string            `json:"supported_effects"`  // allow, deny, require_approval
	EnforcementModes []string            `json:"enforcement_modes"`  // observe, enforce
	Controls         []ControlCapability `json:"controls"`
	AdapterStatus    string              `json:"adapter_status"` // ready, missing, degraded
}

// ControlCapability is a single enforcement control a collector can exercise.
type ControlCapability struct {
	Kind      string   `json:"kind"`      // network.connect, file.read, file.write, exec, secret.read, admission
	Available bool     `json:"available"`
	Adapter   string   `json:"adapter"`   // tetragon, iptables, seccomp, opa
	Effects   []string `json:"effects"`   // what effects this control supports
}

// GetCapabilities returns the enforcement capabilities for a workload.
// GET /api/iga/v2/runtime-policy-capabilities?workload_id=...
func (ctl *CapabilityController) GetCapabilities(c *gin.Context) {
	workloadID := c.Query("workload_id")
	if workloadID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workload_id query parameter required"})
		return
	}

	// Return a default capability set. In production this would query the
	// collector's probe profile to determine actual capabilities.
	caps := WorkloadCapability{
		WorkloadID:       workloadID,
		SupportedEffects: []string{"allow", "deny", "require_approval"},
		EnforcementModes: []string{"observe", "enforce"},
		Controls: []ControlCapability{
			{Kind: "network.connect", Available: true, Adapter: "iptables", Effects: []string{"allow", "deny"}},
			{Kind: "file.read", Available: true, Adapter: "tetragon", Effects: []string{"allow", "deny"}},
			{Kind: "file.write", Available: true, Adapter: "tetragon", Effects: []string{"allow", "deny"}},
			{Kind: "exec", Available: true, Adapter: "tetragon", Effects: []string{"allow", "deny"}},
			{Kind: "secret.read", Available: false, Adapter: "", Effects: nil},
			{Kind: "admission", Available: false, Adapter: "", Effects: nil},
		},
		AdapterStatus: "ready",
	}

	c.JSON(http.StatusOK, gin.H{"data": caps})
}
