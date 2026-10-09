package services

// Runtime availability of the delivery features the /capabilities policy
// block reports (SPEC-iga-phase3-policy.md §4.3; review fix R1a P2 "the
// enforcement and iac capability flags are hard-coded true").
//
// DECISION (review fix): a flag says whether THIS SERVER can deliver the
// feature -- its routes are in the build (served) AND the process has what
// the delivery needs. Per-workspace setup (enforcement_mode, a verified
// binding, an IaC source covering the role) is not folded into the flags:
// it differs per account and per role, and it is reported where it is set
// up and refused with its own §7.12 code at the moment it matters
// (enforcement_not_enabled, binding_not_verified, binding_partial,
// iac_source_missing). §4.3's "a reason per unavailable flag" is honoured:
// each false flag carries the reason below.
//
// What "can deliver" means in this process:
//   - enforcement (J3 direct): the deployment environment is installed
//     (SetGovDeployEnv: AWS access and the binding gate, which need Vault
//     for the enforcement ExternalId). Without it every direct deployment
//     would wait forever.
//   - iac (J2 pull requests): the GitHub App PR adapter is installed
//     (SetGovIaCGitHub, which needs Vault for the App key). Without it an
//     iac_pr target cannot open a pull request.
// Both are installed by cmd/main.go after the Phase 3 schema verifies; a
// replica started with AUTHSEC_DISABLE_POLICY_WORKER=true installs neither
// and reports both false (its own process cannot deliver).

// GovEnforcementAvailable reports whether direct enforcement can run in this
// process, with the reason when it cannot.
func GovEnforcementAvailable() (bool, string) {
	env := currentGovDeployEnv()
	if env.AWS == nil || env.Binding == nil {
		return false, "Direct enforcement is not configured on this server: the deployment environment " +
			"(AWS access through the enforcement role, which needs Vault) is not installed."
	}
	return true, ""
}

// GovIaCAvailable reports whether IaC pull requests can be opened from this
// process, with the reason when they cannot.
func GovIaCAvailable() (bool, string) {
	if DefaultGovIaCGitHub() == nil {
		return false, "IaC pull requests are not configured on this server: the GitHub App adapter " +
			"(which needs Vault for the App key) is not installed."
	}
	return true, ""
}
