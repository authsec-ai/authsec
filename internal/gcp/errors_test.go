package gcp

import (
	"errors"
	"testing"

	"google.golang.org/api/googleapi"
)

// TestClassifyConstraint_SeparatesPolicyFromPermission is the whole point of
// the function. A perimeter violation and an unbound role both arrive as 403,
// and collapsing them sends a customer to grant a role that will change
// nothing.
func TestClassifyConstraint_SeparatesPolicyFromPermission(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "vpc-sc violation type in the error details",
			err:  &googleapi.Error{Code: 403, Message: `Request is prohibited by organization's policy. vpcServiceControlsUniqueIdentifier: abc123`},
			want: ErrVPCServiceControls,
		},
		{
			name: "vpc-sc reason code",
			err:  &googleapi.Error{Code: 403, Message: `SECURITY_POLICY_VIOLATED`},
			want: ErrVPCServiceControls,
		},
		{
			name: "vpc-sc violation constant",
			err:  errors.New(`violations: [{type: VPC_SERVICE_CONTROLS}]`),
			want: ErrVPCServiceControls,
		},
		{
			name: "org policy names a constraint",
			err:  &googleapi.Error{Code: 403, Message: `constraints/iam.disableServiceAccountKeyCreation violated`},
			want: ErrOrgPolicyConstrained,
		},
		{
			name: "an ordinary denial is NOT a constraint",
			err:  &googleapi.Error{Code: 403, Message: `Permission iam.serviceAccounts.list denied on resource`},
			want: nil,
		},
		{
			name: "a not-found is not a constraint",
			err:  &googleapi.Error{Code: 404, Message: `not found`},
			want: nil,
		},
		{
			name: "nil in, nil out",
			err:  nil,
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyConstraint(tc.err)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("got %v, want nil -- an unmatched 403 must fall through to an ordinary denial", got)
				}
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClassifyConstraint_PerimeterWinsOverConstraint: VPC-SC's own message
// mentions an organization policy, so the more specific and more actionable
// answer has to be matched first or every perimeter violation would report as
// a generic policy constraint.
func TestClassifyConstraint_PerimeterWinsOverConstraint(t *testing.T) {
	err := &googleapi.Error{
		Code:    403,
		Message: `Request is prohibited by organization's policy: constraints/something. VPC_SERVICE_CONTROLS`,
	}
	if got := ClassifyConstraint(err); !errors.Is(got, ErrVPCServiceControls) {
		t.Fatalf("got %v, want the perimeter answer, which is the one the customer can act on", got)
	}
}

// TestConstraintReasonCode_IsAShortLabelNotTheProviderMessage. Coverage rows
// are read in places a provider message does not belong: it can carry resource
// names and identifiers from the customer's estate.
func TestConstraintReasonCode_IsAShortLabelNotTheProviderMessage(t *testing.T) {
	if got := ConstraintReasonCode(ErrVPCServiceControls); got != "vpc_service_controls" {
		t.Errorf("got %q, want vpc_service_controls", got)
	}
	if got := ConstraintReasonCode(ErrOrgPolicyConstrained); got != "org_policy_constraint" {
		t.Errorf("got %q, want org_policy_constraint", got)
	}
	if got := ConstraintReasonCode(ErrPermissionDenied); got != "" {
		t.Errorf("got %q, want empty for a non-constraint error", got)
	}
	if got := ConstraintReasonCode(nil); got != "" {
		t.Errorf("got %q, want empty for nil", got)
	}
}
