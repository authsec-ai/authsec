package igaread

// One constructor per limitation code (§5.3 vocabulary), shared by /evidence
// (limitations.go) and the graph routes (traverse_limits.go) -- D-35: "every
// node and edge ... carries limitations computed by the SAME function as
// /evidence". A code is built in exactly one place, so its fields (the ones
// Limitation's doc comment lists) cannot differ between the Evidence panel and
// the canvas: the console has one type per code (§2.14.14 "Contracts behind
// every screen").
//
// Before these existed the graph built its own maps: account_not_connected
// named one account_id where /evidence lists accounts, deny_statements_present
// listed refs where /evidence lists statements, permissions_boundary_present
// and negated_statement carried nothing or other fields. Same code, two
// shapes -- the drift the frozen-contract test (p2_contract_*_test.go) pins
// (D-98).

import (
	"encoding/json"
	"sort"

	"github.com/google/uuid"
)

// LimConditions is conditions_not_evaluated for a Condition block: its keys,
// sorted and distinct ([] when the block has no key-shaped content -- the
// statement is still conditional).
func LimConditions(cond json.RawMessage) Limitation {
	return Limitation{"code": LimConditionsNotEvaluated, "keys": ConditionKeys(cond)}
}

// LimNegated is negated_statement for a statement's text: which negations it
// uses, NotAction before NotResource.
func LimNegated(text statementText) Limitation {
	negs := []string{}
	if len(text.NotActions) > 0 {
		negs = append(negs, "NotAction")
	}
	if len(text.NotResources) > 0 {
		negs = append(negs, "NotResource")
	}
	return Limitation{"code": LimNegatedStatement, "negations": negs}
}

// LimNegatedTrust is negated_statement for a trust statement written with
// NotAction (D-88): a trust row keeps no statement text, only the role's list
// of NotAction statement keys.
func LimNegatedTrust() Limitation {
	return Limitation{"code": LimNegatedStatement, "negations": []string{"NotAction"}}
}

// LimDeny is deny_statements_present for the Deny statements bearing on a
// holder (its own and its groups', §5.3): the whole count, and at most
// LimitationRefCap refs in id order with truncated saying whether that cut
// any. nil when there are none.
func LimDeny(statements []uuid.UUID) Limitation {
	ids := uniqueIDs(statements)
	if len(ids) == 0 {
		return nil
	}
	refs, trunc := capRefs(RefStatement, ids)
	return Limitation{"code": LimDenyStatementsPresent, "count": len(ids), "statements": refs, "truncated": trunc}
}

// LimBoundary is permissions_boundary_present (D-22): holder when the
// identity itself has a boundary (policies: its boundary policies), and for a
// group-held GRANT the current member users that have one (members,
// member_count). nil when neither applies. truncated says whether the member
// list was cut; its count is always whole.
func LimBoundary(own, members []uuid.UUID) Limitation {
	own, members = uniqueIDs(own), uniqueIDs(members)
	if len(own) == 0 && len(members) == 0 {
		return nil
	}
	pol, _ := capRefs(RefPolicy, own)
	mem, trunc := capRefs(RefIdentity, members)
	return Limitation{
		"code": LimPermissionsBoundaryPresent, "holder": len(own) > 0,
		"policies": pol, "members": mem, "member_count": len(members), "truncated": trunc,
	}
}

// LimNotConnected is account_not_connected for the endpoint accounts that are
// not connected, sorted and distinct. nil when there are none.
func LimNotConnected(accounts []string) Limitation {
	var out []string
	for _, a := range accounts {
		if a != "" && !contains(out, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return Limitation{"code": LimAccountNotConnected, "accounts": out}
}

// LimSurface is surface_stale / surface_partial / surface_denied for one
// surface of one account, with the state the run recorded and since when
// (null when not known).
func LimSurface(code, accountID, surface, state string, since any) Limitation {
	return Limitation{"code": code, "account_id": accountID, "surface": surface, "state": state, "since": since}
}

// HolderRestrictions reads, in this snapshot, the restrictions bearing on each
// identity as a HOLDER: the ACTIVE Deny statements of the live attached and
// inline assignments of it and of its live groups, and its OWN live boundary
// policies -- by loadRestrictions, the SAME reader /evidence's
// deny_statements_present and permissions_boundary_present come from, so a
// graph node's restrictions and the Evidence panel of each of its grants can
// never count different statements (D-35, D-78). Both maps are keyed by
// identity, each list distinct and sorted; an identity with neither is
// absent. A group's member boundaries (D-22) are not its own: they bear on
// its grants, and /evidence computes them there.
func (q *Query) HolderRestrictions(ids []uuid.UUID) (deny, boundary map[uuid.UUID][]uuid.UUID, err error) {
	ins := make([]*limInput, 0, len(ids))
	for _, id := range ids {
		id := id
		// A holder with no kind: loadRestrictions reads a group's members only
		// for a group-held GRANT, which this is not.
		ins = append(ins, &limInput{grant: true, holder: &id})
	}
	r, err := loadRestrictions(q, ins, true, true)
	if err != nil {
		return nil, nil, err
	}
	deny, boundary = map[uuid.UUID][]uuid.UUID{}, map[uuid.UUID][]uuid.UUID{}
	for _, id := range ids {
		if d := r.denyOf(id); len(d) > 0 {
			deny[id] = d
		}
		if b := uniqueIDs(r.boundary[id]); len(b) > 0 {
			boundary[id] = b
		}
	}
	return deny, boundary, nil
}
