// setup-reader.sh embed and render — the customer-run GCP reader setup
// script. Mirrors internal/awsdiscovery's CloudFormationTemplate embed
// pattern exactly: the template a customer runs is exactly the one this
// build expects, no outbound fetch needed to onboard, and it lives
// alongside the rest of the gcp package rather than in its own top-level
// directory, matching where internal/awsdiscovery keeps
// authsec-aws-discovery-role.yaml.
package gcp

import (
	_ "embed"
	"fmt"
	"strings"
	"text/template"
)

//go:embed setup-reader.sh
var rawTemplate string

// Version identifies the permission set and binding shape this script
// version grants — the WIF/json_key analog of awsdiscovery.TemplateVersion,
// recorded on the connector (GCPConnectorAttrs.SetupScriptVersion) so an
// operator can find connectors still on an older script once the role set or
// binding shape changes.
const Version = "2026-09-02"

var tmpl = template.Must(template.New("setup-reader.sh").Parse(rawTemplate))

// Data is everything the template needs. Every field is either the
// customer's own input (ReaderProjectID, ScopeKind, ScopeID) or a pure
// function of it (PoolID/ProviderID/WIFSubject via
// internal/gcp.DeriveWIFParams, RoleGrantCommands via
// internal/gcp.CandidateReaderRoles) — nothing here is secret, and nothing
// here is randomly generated per render, so re-fetching the onboarding
// package produces byte-identical WIF derivation values (though a fresh
// SetupScriptVersion/RoleSetStatus if either changed between calls).
type Data struct {
	ReaderProjectID    string
	ScopeKind          string
	ScopeID            string
	PoolID             string
	ProviderID         string
	WIFSubject         string
	IssuerURL          string
	RoleSetStatus      string
	SetupScriptVersion string
	// RoleGrantCommands are fully-formed gcloud commands, one per role in
	// internal/gcp.CandidateReaderRoles, already directed at the right
	// resource type (organizations/folders/projects add-iam-policy-binding)
	// for ScopeKind — computed in Go (RoleGrantCommandsFor), not in the
	// template, so the template has no per-scope-kind branching logic to get
	// wrong.
	RoleGrantCommands []string
}

// Render fills the embedded template with data and returns the complete
// shell script text.
func Render(data Data) (string, error) {
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render setup-reader.sh: %w", err)
	}
	return buf.String(), nil
}
