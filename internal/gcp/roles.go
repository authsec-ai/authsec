package gcp

import (
	"fmt"

	"github.com/authsec-ai/authsec/models"
)

// RoleSetStatusConfirmed and RoleSetStatusCandidate are the two values
// GCPConnectorAttrs.RoleSetStatus takes (models/cloud_discovery.go). Not a
// CHECK-constrained enum — cloud_connector.attrs is free-form jsonb — but
// exported here so the controller and any later reader compare against the
// same two strings rather than re-typing them.
const (
	RoleSetStatusConfirmed = "confirmed"
	RoleSetStatusCandidate = "candidate_pending_GCP-01"
)

// CandidateReaderRoles is the reader role set GCP-04's setup script grants,
// bound at whichever scope_kind the customer picked (org, folder, or
// project) — never project-only, per the scoping finding below.
//
// This is authsec/docs/gcp/feasibility-validation.md's "Final candidate
// reader role list" as of this writing, NOT gcp-test-environment-setup.md
// Phase 2's original four-role baseline. That baseline is NOT used here even
// though the ledger's overall status is PARTIAL (not COMPLETE) — the literal
// GCP-04 ticket text says to fall back to it when the ledger isn't COMPLETE,
// but Phase 2's own baseline names `roles/resourcemanager.projectViewer`,
// which GCP-01 proved does not exist as a real GCP role (live-tested:
// `gcloud iam roles describe roles/resourcemanager.projectViewer` returns
// "not found"). Shipping a known-nonexistent role name in a customer-facing
// script would make the script fail every time it runs, which is a strictly
// worse outcome than using the ledger's own corrected list a session early.
// The two live-access gaps that keep the ledger's overall status at PARTIAL
// (GKE Workload Identity untested — billing unavailable; the WIF mechanism's
// full success round-trip untested — no reachable issuer) are both unrelated
// to the role list itself, which the ledger recorded as fully live-verified.
//
// RoleSetStatusCandidate is still used below (not RoleSetStatusConfirmed) —
// this deviation is about not shipping a role that doesn't exist, not a claim
// that GCP-01 has reached COMPLETE. Re-evaluate both the constant list and
// RoleSetStatus together once GCP-01's ledger status line actually reads
// COMPLETE.
var CandidateReaderRoles = []string{
	"roles/iam.serviceAccountViewer",
	"roles/iam.roleViewer",
	"roles/cloudasset.viewer",
	"roles/browser",
}

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

	cmds := make([]string, 0, len(CandidateReaderRoles))
	for _, role := range CandidateReaderRoles {
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
		cmds = append(cmds, fmt.Sprintf(
			"gcloud %s add-iam-policy-binding %s \\\n  --member=\"serviceAccount:%s\" --role=%s --condition=None",
			target, scopeID, readerSAEmailVar, role,
		))
	}
	return cmds
}
