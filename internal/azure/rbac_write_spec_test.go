package azure

import "testing"

// A restore puts back what was removed: the condition with its version, and
// the description.
func TestSpecOfKeepsConditionAndDescription(t *testing.T) {
	var a RoleAssignment
	a.Name = "a1"
	a.Properties.Scope, a.Properties.RoleDefinitionID, a.Properties.PrincipalID, a.Properties.PrincipalType = "/subscriptions/s", "/r", "p", "ServicePrincipal"
	a.Properties.Condition, a.Properties.ConditionVersion, a.Properties.Description = "@Resource[x] StringEquals 'y'", "2.0", "break-glass"
	s := SpecOf(a)
	if s.Condition != a.Properties.Condition || s.ConditionVersion != "2.0" || s.Description != "break-glass" || s.Name != "a1" {
		t.Fatalf("spec %+v", s)
	}
}
