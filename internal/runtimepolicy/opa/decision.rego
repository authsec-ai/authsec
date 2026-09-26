package authsec.runtime

import rego.v1

# Pinned typed template for authsec.runtime.v1. The compiler emits this
# module unchanged and puts the resolved rules in data. Custom Rego is not
# loaded here. Builtins that do I/O are removed from the evaluator's
# capabilities, so this module cannot call them even if it tried.

in_scope if {
	input.workload_id in data.targets.workload_ids
}

quarantined if input.quarantined == true

leased if {
	input.approval_lease.id != ""
	input.approval_lease.resource_id == input.resource_id
}

deny_ids contains rule.id if {
	in_scope
	not quarantined
	some rule in data.rules
	rule.effect == "deny"
	rule_matches(rule)
}

approval_ids contains rule.id if {
	in_scope
	not quarantined
	some rule in data.rules
	rule.effect == "require_approval"
	rule_matches(rule)
}

allow_ids contains rule.id if {
	in_scope
	not quarantined
	some rule in data.rules
	rule.effect == "allow"
	rule_matches(rule)
}

decision := {
	"effect": "deny",
	"reason_codes": ["quarantine"],
	"matched_rule_ids": [],
	"policy_revision": data.policy_revision,
	"obligations": [],
} if {
	quarantined
}

decision := {
	"effect": "deny",
	"reason_codes": ["explicit_deny"],
	"matched_rule_ids": [id | some id in deny_ids],
	"policy_revision": data.policy_revision,
	"obligations": [],
} if {
	not quarantined
	count(deny_ids) > 0
}

decision := {
	"effect": "allow",
	"reason_codes": ["approval_lease"],
	"matched_rule_ids": [id | some id in approval_ids],
	"policy_revision": data.policy_revision,
	"obligations": [],
} if {
	not quarantined
	count(deny_ids) == 0
	count(approval_ids) > 0
	leased
}

decision := {
	"effect": "require_approval",
	"reason_codes": ["approval_required"],
	"matched_rule_ids": [id | some id in approval_ids],
	"policy_revision": data.policy_revision,
	"obligations": [ob | some rule in data.rules; rule.id in approval_ids; ob := {"type": "approval", "adapter": rule.adapter, "rule_id": rule.id}],
} if {
	not quarantined
	count(deny_ids) == 0
	count(approval_ids) > 0
	not leased
}

decision := {
	"effect": "allow",
	"reason_codes": ["rule_allow"],
	"matched_rule_ids": [id | some id in allow_ids],
	"policy_revision": data.policy_revision,
	"obligations": [],
} if {
	not quarantined
	count(deny_ids) == 0
	count(approval_ids) == 0
	count(allow_ids) > 0
}

decision := {
	"effect": "deny",
	"reason_codes": ["default_deny"],
	"matched_rule_ids": [],
	"policy_revision": data.policy_revision,
	"obligations": [],
} if {
	in_scope
	not quarantined
	count(deny_ids) == 0
	count(approval_ids) == 0
	count(allow_ids) == 0
}

decision := {
	"effect": "deny",
	"reason_codes": ["outside_policy_scope"],
	"matched_rule_ids": [],
	"policy_revision": data.policy_revision,
	"obligations": [],
} if {
	not in_scope
	not quarantined
}

rule_matches(rule) if {
	rule.action == input.action
	rule.action == "network.connect"
	input.resource_id == rule.resource_id
}

rule_matches(rule) if {
	rule.action == input.action
	startswith(rule.action, "file.")
	path_matches(input.native_target.path, rule.path)
}

rule_matches(rule) if {
	rule.action == input.action
	rule.action == "exec"
}

rule_matches(rule) if {
	rule.action == input.action
	rule.action == "secret.read"
	input.resource_id == rule.resource_id
}

rule_matches(rule) if {
	rule.action == input.action
	rule.action == "admission"
}

path_matches(got, want) if got == want

path_matches(got, want) if {
	endswith(want, "/**")
	prefix := trim_suffix(want, "**")
	startswith(got, prefix)
}
