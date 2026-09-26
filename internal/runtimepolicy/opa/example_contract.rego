package authsec.runtime

import rego.v1

# §14.2 contract example. CI executes this under the pinned OPA. It is not
# the production template; decision.rego is.

default allow := false

allow if {
	input.action == "network.connect"
	input.workload_id == data.target.workload_id
	input.resource_id in data.target.allowed_endpoints
	not input.quarantined
}

decision := {
	"effect": "allow",
	"reason_codes": ["approved_endpoint"],
	"policy_revision": data.target.policy_revision,
} if {
	allow
}

decision := {
	"effect": "deny",
	"reason_codes": ["endpoint_not_allowed"],
	"policy_revision": data.target.policy_revision,
} if {
	not allow
}
