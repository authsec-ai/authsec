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

	"github.com/authsec-ai/authsec/models"
)

//go:embed setup-reader.sh
var rawTemplate string

// Version identifies the permission set and binding shape this script
// version grants — the WIF/json_key analog of awsdiscovery.TemplateVersion,
// recorded on the connector (GCPConnectorAttrs.SetupScriptVersion) so an
// operator can find connectors still on an older script once the role set or
// binding shape changes.
const Version = "2026-09-09"

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
	// CoreServices and DiscoveryServices are internal/gcp's two API lists,
	// rendered into the script separately because the script treats them
	// differently: core is fatal, discovery is best-effort. Passed through
	// rather than hardcoded in the template so the script a customer runs and
	// the list the Google Authentication path enables cannot diverge -- they
	// were two separate literals before, exactly the kind of pair that drifts
	// silently the first time one of them is extended.
	CoreServices      []string
	DiscoveryServices []string
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

/* --------------------------- reader role set ------------------------------- */

// RoleSetStatusConfirmed and RoleSetStatusCandidate are the two values
// GCPConnectorAttrs.RoleSetStatus takes (models/cloud_discovery.go). Not a
// CHECK-constrained enum — cloud_connector.attrs is free-form jsonb — but
// exported here so the controller and any later reader compare against the
// same two strings rather than re-typing them.
const (
	RoleSetStatusConfirmed = "confirmed"
	RoleSetStatusCandidate = "candidate_pending_GCP-01"
)

// ReaderRoleSetVersion labels the role set below. It is a stable, explicit
// string bumped BY HAND whenever ReaderRolesFor's output changes -- not a hash
// or anything derived. Recorded per connector so an operator can find
// connectors still onboarded against an earlier, narrower set once a later
// phase adds roles.
//
// v1 was the four-role set that shipped with GCP onboarding
// (serviceAccountViewer, roleViewer, cloudasset.viewer, browser). v2 completes
// the discovery plan's P1 set by adding iam.securityReviewer and by using the
// org-level role viewer where the scope is an organization.
const ReaderRoleSetVersion = "gcp-reader-p1-v2"

// baseReaderRoles are granted at every scope kind. The role-viewer role is NOT
// here: which one is correct depends on the scope kind, so ReaderRolesFor adds
// it.
//
// roles/iam.securityReviewer is what makes org-wide allow-policy reads and
// getIamPolicy across resource types possible, and it is also how auditConfigs
// become readable. It is broad by design; if a customer objects, the fallback
// is a custom role, which is a conversation to have rather than a silent
// narrowing here.
var baseReaderRoles = []string{
	"roles/iam.serviceAccountViewer",
	"roles/iam.securityReviewer",
	"roles/cloudasset.viewer",
	"roles/browser",
}

// RoleViewerFor returns the role that lets the reader read role DEFINITIONS --
// iam.roles.get/.list -- at scopeKind.
//
// The two are not interchangeable. roles/iam.organizationRoleViewer is what
// grants org-wide visibility of custom role definitions, which is what
// expanding a binding found by searchAllIamPolicies actually needs; but it is
// an organization-level role, so binding it at a folder or project is not a
// narrower version of the same thing. roles/iam.roleViewer is the right role
// there.
//
// LIVE-CHECK OWED: whether GCP accepts organizationRoleViewer only at
// organizations, or at folders too, has not been confirmed against a real
// organization. This split is the conservative reading. If the live API
// disagrees, the API wins -- record what it does and change this, do not code
// around it.
func RoleViewerFor(scopeKind string) string {
	if scopeKind == models.CloudScopeOrg {
		return "roles/iam.organizationRoleViewer"
	}
	return "roles/iam.roleViewer"
}

// ReaderRolesFor is the reader role set to grant at scopeKind, bound at
// whichever scope the customer picked (org, folder or project) -- never
// project-only.
//
// This is the discovery plan's P1 set and nothing beyond it. The P2 roles
// (deny, Principal Access Boundary), P5 (workload hosts, Vertex, Agent
// Registry) and P7 (private logs, activity analysis) are deliberately NOT
// granted here: two of them carry unresolved decisions -- roles/aiplatform.viewer
// also permits invoking an agent, and no read-only predefined role exists for
// iam.policybindings -- and granting them quietly ahead of that review would
// be exactly the silent scope creep this set exists to prevent. The permission
// probe reports those surfaces as unreachable instead, so the gap is visible
// rather than assumed.
func ReaderRolesFor(scopeKind string) []string {
	roles := make([]string, 0, len(baseReaderRoles)+1)
	roles = append(roles, baseReaderRoles...)
	return append(roles, RoleViewerFor(scopeKind))
}

// CandidateReaderRoles is the project-scope reader set, retained as the
// scope-kind-free answer for callers that only need "roughly what do we grant"
// (the onboarding package's informational role_set field). Anything that
// actually grants must use ReaderRolesFor, so an org connector gets the
// org-level role viewer.
var CandidateReaderRoles = ReaderRolesFor(models.CloudScopeProject)

// CurrentRoleSetStatus is which of the two RoleSetStatus* values
// CandidateReaderRoles currently corresponds to. A single source of truth so
// the controller never has to independently decide which label matches which
// list.
const CurrentRoleSetStatus = RoleSetStatusCandidate

// readerSAEmailVar is the shell variable name setup-reader.sh's own template
// defines (READER_SA_EMAIL) — referenced verbatim, in shell syntax, in every
// generated grant command, never resolved on the Go side. The script sets it
// once, from the reader SA it just created; every gcloud command generated
// here reuses that same shell variable rather than a literal email, so the
// script never has two different ideas of what the reader SA's address is.
const readerSAEmailVar = "${READER_SA_EMAIL}"

// RoleGrantCommands renders one gcloud ... add-iam-policy-binding command per
// role in CandidateReaderRoles, directed at whichever GCP resource type
// scopeKind names — organizations, folders, or projects each have their own
// gcloud subcommand, and there is no single command that works for all
// three. Computed here, in Go, rather than as branching logic inside
// gcp/scripts/setup-reader.sh's template, so the template has nothing to get
// wrong per scope kind.
func RoleGrantCommands(scopeKind, scopeID string) []string {
	var target string
	switch scopeKind {
	case models.CloudScopeOrg:
		target = "organizations"
	case models.CloudScopeFolder:
		target = "resource-manager folders"
	default:
		// project, and any scope kind this connector's onboarding doesn't
		// actually support (account, subscription) — those are rejected before
		// this is ever called; project is the common, safe default shape.
		target = "projects"
	}

	roles := ReaderRolesFor(scopeKind)
	cmds := make([]string, 0, len(roles))
	for _, role := range roles {
		// --condition=None is required, not cosmetic: gcloud refuses to add an
		// unconditional binding non-interactively to any policy that already
		// carries a conditional binding ("Adding a binding without specifying
		// a condition to a policy containing conditions is prohibited in
		// non-interactive mode"). Live-confirmed against a real org/project
		// that already had a conditional binding from an earlier fixture —
		// the unmodified command failed there and succeeded unmodified on a
		// clean scope. Every reader-role grant here is meant to be
		// unconditional, so this is the correct binding in both cases, not a
		// workaround that changes behavior on a clean scope.
		// The trailing `|| echo` is not cosmetic. The script runs under
		// `set -e`, so a grant the operator is not permitted to make would
		// otherwise abort it here — before the workload identity pool,
		// provider and binding below are created. The customer would then have
		// nothing to paste back, and the credential exchange would fail later
		// with an error nowhere near the actual cause.
		//
		// A role that could not be granted is a capability limit, not a failed
		// onboarding: the permission probe measures what was actually granted,
		// so a connector that comes up short says so rather than claiming
		// access it does not have.
		cmds = append(cmds, fmt.Sprintf(
			"gcloud %s add-iam-policy-binding %s \\\n"+
				"  --member=\"serviceAccount:%s\" --role=%s --condition=None \\\n"+
				"  || echo \"  WARNING: could not grant %s — AuthSec will report the surfaces it covers as unavailable\"",
			target, scopeID, readerSAEmailVar, role, role,
		))
	}
	return cmds
}
