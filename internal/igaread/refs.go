package igaread

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Typed references (§5.2). A bare UUID never identifies an object on its own:
// every object and claim in a response is "<type>:<uuid>".
const (
	// Objects.
	RefWorkload          = "workload"           // iga_workload
	RefIdentity          = "identity"           // iga_identity_accounts (role, user, group)
	RefExternalPrincipal = "external_principal" // iga_external_principal
	RefResource          = "resource"           // iga_resources
	RefPolicy            = "policy"             // iga_policy
	RefStatement         = "statement"          // iga_entitlements (provider = 'aws')

	// Claims.
	RefRelationship   = "relationship"    // iga_relationship
	RefObservedAccess = "observed_access" // iga_observed_access (graph=v2; not an /evidence type)
	RefAssignment     = "assignment"      // iga_policy_assignment
	RefGrant          = "grant"           // iga_access_edges
	RefTarget         = "target"          // iga_entitlement_target
	RefPresence       = "presence"        // an object's support rows (iga_object_support)
	RefCoverage       = "coverage"        // coverage:<run id>:<surface>

	// Collection-side references the pipeline and scan views use.
	RefScanRun   = "cloud_scan_run"
	RefConnector = "cloud_connector"
)

// refTables is the table each object and row-backed claim type reads from.
var refTables = map[string]string{
	RefWorkload:          "iga_workload",
	RefIdentity:          "iga_identity_accounts",
	RefExternalPrincipal: "iga_external_principal",
	RefResource:          "iga_resources",
	RefPolicy:            "iga_policy",
	RefStatement:         "iga_entitlements",
	RefRelationship:      "iga_relationship",
	RefAssignment:        "iga_policy_assignment",
	RefGrant:             "iga_access_edges",
	RefTarget:            "iga_entitlement_target",
	RefPresence:          "iga_object_support",
	RefScanRun:           "cloud_scan_run",
	RefConnector:         "cloud_connector",
}

// TableOf is the table a typed reference names ("" for coverage, which is not
// a row, or an unknown type).
func TableOf(refType string) string { return refTables[refType] }

// Ref is a parsed typed reference. Coverage refs carry their surface.
type Ref struct {
	Type    string
	ID      uuid.UUID
	Surface string // coverage only
}

func (r Ref) String() string {
	if r.Type == RefCoverage {
		return fmt.Sprintf("%s:%s:%s", RefCoverage, r.ID, r.Surface)
	}
	return r.Type + ":" + r.ID.String()
}

// R renders a typed reference.
func R(refType string, id uuid.UUID) string { return refType + ":" + id.String() }

// RPtr renders a typed reference, or nil (JSON null) when id is nil.
func RPtr(refType string, id *uuid.UUID) any {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	return R(refType, *id)
}

// CoverageRef renders coverage:<run id>:<surface>.
func CoverageRef(runID uuid.UUID, surface string) string {
	return Ref{Type: RefCoverage, ID: runID, Surface: surface}.String()
}

// ParseRef parses "<type>:<uuid>" (or coverage:<run>:<surface>). Unknown types
// and malformed ids are errors.
func ParseRef(s string) (Ref, error) {
	typ, rest, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || typ == "" {
		return Ref{}, fmt.Errorf("not a typed reference: %q", s)
	}
	if typ == RefCoverage {
		idPart, surface, ok := strings.Cut(rest, ":")
		if !ok || surface == "" {
			return Ref{}, fmt.Errorf("coverage reference needs a run and a surface: %q", s)
		}
		id, err := uuid.Parse(idPart)
		if err != nil {
			return Ref{}, fmt.Errorf("bad run id in %q", s)
		}
		return Ref{Type: RefCoverage, ID: id, Surface: surface}, nil
	}
	if _, known := refTables[typ]; !known {
		return Ref{}, fmt.Errorf("unknown reference type %q", typ)
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return Ref{}, fmt.Errorf("bad id in %q", s)
	}
	return Ref{Type: typ, ID: id}, nil
}

// ParseRefParam parses a query parameter that must be a typed reference of
// one of the allowed types; anything else is 400 invalid_parameter.
func ParseRefParam(param, s string, allowed ...string) (Ref, *Error) {
	ref, err := ParseRef(s)
	if err != nil {
		return Ref{}, InvalidParameter(param, err.Error())
	}
	if len(allowed) == 0 {
		return ref, nil
	}
	for _, a := range allowed {
		if ref.Type == a {
			return ref, nil
		}
	}
	return Ref{}, InvalidParameter(param, fmt.Sprintf("%s references are not accepted here", ref.Type))
}

// RouteID parses a type-specific route parameter (/identities/:id). It accepts
// the bare UUID, or the typed reference of THIS route's type. Anything else --
// including another type's reference -- is 404 not_found, with no hint (§5.2).
func RouteID(refType, raw string) (uuid.UUID, *Error) {
	raw = strings.TrimSpace(raw)
	if typ, rest, ok := strings.Cut(raw, ":"); ok {
		if typ != refType {
			return uuid.Nil, NotFound()
		}
		raw = rest
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, NotFound()
	}
	return id, nil
}
