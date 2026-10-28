package models

// Canonical primitive catalog. Each primitive is a named capability that can
// appear in a V2 policy rule. The catalog is the single source of truth for
// what the enforcement stack can discover and protect.
//
// Primitives are backend-agnostic. The compiler maps each primitive to
// backend-specific controls during policy compilation.

// Primitive is a canonical enforcement primitive in the catalog.
type Primitive struct {
	ID                string              `json:"id"`
	DisplayName       string              `json:"display_name"`
	Description       string              `json:"description"`
	InputSchema       PrimitiveInputSchema `json:"input_schema"`
	Effects           []string            `json:"effects"`            // allowed effects: allow, deny, require_approval
	Constraints       []PrimitiveConstraint `json:"constraints"`
	DiscoverySources  []string            `json:"discovery_sources"`  // where evidence comes from
	EnforcementOwners []string            `json:"enforcement_owners"` // which adapter handles enforcement
	UpdateBehavior    string              `json:"update_behavior"`    // "replacement", "incremental"
	ProbeType         string              `json:"probe_type"`         // "active", "passive", "none"
	Limitations       []string            `json:"limitations,omitempty"`
}

// PrimitiveInputSchema describes the expected input fields for a primitive.
type PrimitiveInputSchema struct {
	Fields []PrimitiveField `json:"fields"`
}

// PrimitiveField is one input parameter for a primitive.
type PrimitiveField struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "string", "int", "bool", "uuid", "path_glob"
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// PrimitiveConstraint defines a validation rule for a primitive.
type PrimitiveConstraint struct {
	Field      string `json:"field"`
	Rule       string `json:"rule"`       // "non_empty", "valid_uuid", "valid_path", "one_of"
	AllowedValues []string `json:"allowed_values,omitempty"`
}

// PrimitiveCoverage tracks the discovery and enforcement status of a single
// primitive for a specific agent or workload.
type PrimitiveCoverage struct {
	PrimitiveID       string `json:"primitive_id"`
	DiscoveryStatus   string `json:"discovery_status"`   // "discovered", "undiscovered", "not_applicable"
	EnforcementStatus string `json:"enforcement_status"` // "enforceable", "observe_only", "not_supported", "blocked"
	Backend           string `json:"backend,omitempty"`   // "authsec", "openshell"
	Profile           string `json:"profile,omitempty"`
	Reason            string `json:"reason,omitempty"`
	Evidence          string `json:"evidence,omitempty"` // last evidence reference
}

// Coverage status constants.
const (
	DiscoveryStatusDiscovered     = "discovered"
	DiscoveryStatusUndiscovered   = "undiscovered"
	DiscoveryStatusNotApplicable  = "not_applicable"

	EnforcementStatusEnforceable  = "enforceable"
	EnforcementStatusObserveOnly  = "observe_only"
	EnforcementStatusNotSupported = "not_supported"
	EnforcementStatusBlocked      = "blocked"
)

// Canonical primitive IDs. These are the only valid values for PolicyV2Rule.Primitive.
const (
	PrimitiveFileRead        = "file.read"
	PrimitiveFileWrite       = "file.write"
	PrimitiveProcessHarden   = "process.harden"
	PrimitiveProcessExec     = "process.exec"
	PrimitiveNetworkConnect  = "network.connect"
	PrimitiveUnixSocket      = "unix_socket.connect"
	PrimitiveSecretRead      = "secret.read"
	PrimitiveLLMInvoke       = "llm.invoke"
	PrimitiveGitHubOperation = "github.operation"
	PrimitiveDeviceOpen      = "device.open"
	PrimitiveDBOperation     = "db.operation"
	PrimitiveRemoteSession   = "remote.session"
)

// ValidPrimitiveIDs returns all canonical primitive identifiers.
func ValidPrimitiveIDs() []string {
	return []string{
		PrimitiveFileRead,
		PrimitiveFileWrite,
		PrimitiveProcessHarden,
		PrimitiveProcessExec,
		PrimitiveNetworkConnect,
		PrimitiveUnixSocket,
		PrimitiveSecretRead,
		PrimitiveLLMInvoke,
		PrimitiveGitHubOperation,
		PrimitiveDeviceOpen,
		PrimitiveDBOperation,
		PrimitiveRemoteSession,
	}
}

// IsValidPrimitive reports whether the given id is a known primitive.
func IsValidPrimitive(id string) bool {
	for _, p := range ValidPrimitiveIDs() {
		if p == id {
			return true
		}
	}
	return false
}

// CatalogPrimitives returns the full canonical primitive catalog with metadata
// for each primitive. This is the reference source for UI display, validation,
// and coverage tracking.
func CatalogPrimitives() []Primitive {
	return []Primitive{
		{
			ID: PrimitiveFileRead, DisplayName: "File Read", Description: "Read access to file system paths.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "path", Type: "path_glob", Required: true, Description: "File path or glob pattern."},
			}},
			Effects: []string{"allow", "deny"}, DiscoverySources: []string{"tetragon", "audit_log", "procfs"},
			EnforcementOwners: []string{"landlock", "tetragon"}, UpdateBehavior: "replacement",
			ProbeType: "active",
		},
		{
			ID: PrimitiveFileWrite, DisplayName: "File Write", Description: "Write access to file system paths.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "path", Type: "path_glob", Required: true, Description: "File path or glob pattern."},
			}},
			Effects: []string{"allow", "deny"}, DiscoverySources: []string{"tetragon", "audit_log", "procfs"},
			EnforcementOwners: []string{"landlock", "tetragon"}, UpdateBehavior: "replacement",
			ProbeType: "active",
		},
		{
			ID: PrimitiveProcessHarden, DisplayName: "Process Hardening", Description: "Drop privileges, capabilities, and apply seccomp.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "capabilities", Type: "string", Required: false, Description: "Comma-separated capability list to drop."},
				{Name: "no_new_privs", Type: "bool", Required: false, Description: "Set no_new_privs flag."},
			}},
			Effects: []string{"allow", "deny"}, DiscoverySources: []string{"procfs", "audit_log"},
			EnforcementOwners: []string{"seccomp", "launcher"}, UpdateBehavior: "replacement",
			ProbeType: "passive",
		},
		{
			ID: PrimitiveProcessExec, DisplayName: "Process Execution", Description: "Control which processes can execute.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "path", Type: "path_glob", Required: false, Description: "Executable path or glob."},
			}},
			Effects: []string{"allow", "deny"}, DiscoverySources: []string{"tetragon", "audit_log", "procfs"},
			EnforcementOwners: []string{"tetragon", "seccomp", "launcher"}, UpdateBehavior: "replacement",
			ProbeType: "active",
		},
		{
			ID: PrimitiveNetworkConnect, DisplayName: "Network Connect", Description: "Outbound network connection to address and port.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "resource_id", Type: "uuid", Required: false, Description: "Resource UUID for resolved endpoints."},
				{Name: "address", Type: "string", Required: false, Description: "Destination address."},
				{Name: "port", Type: "int", Required: false, Description: "Destination port."},
				{Name: "protocol", Type: "string", Required: false, Description: "Protocol (tcp, udp)."},
			}},
			Effects: []string{"allow", "deny", "require_approval"}, DiscoverySources: []string{"tetragon", "conntrack", "dns"},
			EnforcementOwners: []string{"network_namespace", "cni", "gateway"}, UpdateBehavior: "replacement",
			ProbeType: "active",
		},
		{
			ID: PrimitiveUnixSocket, DisplayName: "Unix Socket Connect", Description: "Connection to a Unix domain socket.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "path", Type: "path_glob", Required: true, Description: "Socket path."},
			}},
			Effects: []string{"allow", "deny"}, DiscoverySources: []string{"tetragon", "procfs"},
			EnforcementOwners: []string{"landlock", "tetragon"}, UpdateBehavior: "replacement",
			ProbeType: "active",
		},
		{
			ID: PrimitiveSecretRead, DisplayName: "Secret Read", Description: "Read a secret through the managed broker.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "resource_id", Type: "uuid", Required: true, Description: "Secret resource UUID."},
				{Name: "adapter", Type: "string", Required: true, Description: "Broker adapter name."},
			}},
			Effects: []string{"allow", "deny", "require_approval"}, DiscoverySources: []string{"broker_log", "env_scan"},
			EnforcementOwners: []string{"gateway", "broker"}, UpdateBehavior: "incremental",
			ProbeType: "none",
		},
		{
			ID: PrimitiveLLMInvoke, DisplayName: "LLM Invoke", Description: "Invocation of an LLM model endpoint.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "resource_id", Type: "uuid", Required: false, Description: "LLM resource UUID."},
				{Name: "model", Type: "string", Required: false, Description: "Model identifier."},
			}},
			Effects: []string{"allow", "deny", "require_approval"}, DiscoverySources: []string{"gateway_log", "network"},
			EnforcementOwners: []string{"gateway"}, UpdateBehavior: "incremental",
			ProbeType: "none",
		},
		{
			ID: PrimitiveGitHubOperation, DisplayName: "GitHub Operation", Description: "GitHub API or Git transport operation.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "resource_id", Type: "uuid", Required: false, Description: "GitHub resource UUID."},
				{Name: "operation", Type: "string", Required: false, Description: "API operation type."},
				{Name: "repository", Type: "string", Required: false, Description: "Repository scope."},
			}},
			Effects: []string{"allow", "deny", "require_approval"}, DiscoverySources: []string{"gateway_log", "git_transport"},
			EnforcementOwners: []string{"gateway"}, UpdateBehavior: "incremental",
			ProbeType: "none",
		},
		{
			ID: PrimitiveDeviceOpen, DisplayName: "Device Open", Description: "Direct device access (e.g. /dev nodes).",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "path", Type: "path_glob", Required: true, Description: "Device path."},
			}},
			Effects: []string{"allow", "deny"}, DiscoverySources: []string{"tetragon", "audit_log"},
			EnforcementOwners: []string{"cgroup_device", "landlock"}, UpdateBehavior: "replacement",
			ProbeType: "passive",
			Limitations: []string{"Requires cgroup v2 device controller."},
		},
		{
			ID: PrimitiveDBOperation, DisplayName: "Database Operation", Description: "Database query or command execution.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "resource_id", Type: "uuid", Required: false, Description: "Database resource UUID."},
				{Name: "operation", Type: "string", Required: false, Description: "Operation type (read, write, ddl)."},
			}},
			Effects: []string{"allow", "deny", "require_approval"}, DiscoverySources: []string{"gateway_log", "network"},
			EnforcementOwners: []string{"gateway"}, UpdateBehavior: "incremental",
			ProbeType: "none",
		},
		{
			ID: PrimitiveRemoteSession, DisplayName: "Remote Session", Description: "Remote shell or RDP session.",
			InputSchema: PrimitiveInputSchema{Fields: []PrimitiveField{
				{Name: "resource_id", Type: "uuid", Required: false, Description: "Target host resource UUID."},
				{Name: "protocol", Type: "string", Required: false, Description: "Session protocol (ssh, rdp)."},
			}},
			Effects: []string{"allow", "deny", "require_approval"}, DiscoverySources: []string{"audit_log", "session_log"},
			EnforcementOwners: []string{"gateway", "session_broker"}, UpdateBehavior: "incremental",
			ProbeType: "none",
		},
	}
}
