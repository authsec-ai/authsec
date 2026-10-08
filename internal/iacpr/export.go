package iacpr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// J1 export (§1.1, §7.3 GET .../export, §8.11): the approved documents plus
// AWS CLI and Terraform snippets the customer applies with their own tools.
// The steps are the plan's ops in order (§8.5 / §11 tables); AuthSec runs
// none of them for export.

// Artifact is one plan's downloadable export.
type Artifact struct {
	PlanKind    string            `json:"plan_kind"`
	RoleARN     string            `json:"role_arn"`
	RoleID      string            `json:"role_id"`
	Description Description       `json:"description"`
	Documents   map[string]string `json:"documents"` // file name -> canonical JSON
	CLI         []string          `json:"aws_cli"`
	Terraform   string            `json:"terraform"`
	Fallback    *Fallback         `json:"iac_fallback,omitempty"`
}

func docFile(hash string) string {
	return "policy-" + strings.TrimPrefix(hash, "sha256:")[:12] + ".json"
}

func cliTags(tags map[string]string) string {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, "Key="+k+",Value="+tags[k])
	}
	return strings.Join(parts, " ")
}

// Export builds a plan's artifact. deploymentID substitutes the change tag
// placeholder (empty: "<deployment id>").
func Export(p igagov.Plan, role RoleTarget, docs map[string]string, deploymentID string) (Artifact, error) {
	if deploymentID == "" {
		deploymentID = "<deployment id>"
	}
	a := Artifact{PlanKind: p.Kind, RoleARN: role.ARN, RoleID: role.RoleID, Description: Describe(p, role, nil),
		Documents: map[string]string{}, CLI: []string{}}
	addDoc := func(h string) (string, error) {
		d, ok := docs[h]
		if !ok {
			return "", fmt.Errorf("iacpr: document %s is not archived", h)
		}
		f := docFile(h)
		a.Documents[f] = d
		return f, nil
	}
	sub := func(tags map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range tags {
			if v == igagov.DeploymentPlaceholder {
				v = deploymentID
			}
			out[k] = v
		}
		return out
	}
	var tf strings.Builder
	q := strconv.Quote
	for _, op := range p.Ops {
		switch op.Op {
		case igagov.OpCreatePolicy:
			f, err := addDoc(op.DocumentHash)
			if err != nil {
				return a, err
			}
			cmd := fmt.Sprintf("aws iam create-policy --policy-name %s --path %s --policy-document file://%s", op.PolicyName, op.Path, f)
			if len(op.Tags) > 0 {
				cmd += " --tags " + cliTags(sub(op.Tags))
			}
			a.CLI = append(a.CLI, cmd)
			blk, err := (&tfSource{}).policyBlock(op.PolicyName, op.Path, docs[op.DocumentHash], sub(op.Tags))
			if err != nil {
				return a, err
			}
			tf.WriteString(blk + "\n")
		case igagov.OpCreatePolicyVersion:
			f, err := addDoc(op.DocumentHash)
			if err != nil {
				return a, err
			}
			a.CLI = append(a.CLI, fmt.Sprintf("aws iam create-policy-version --policy-arn %s --policy-document file://%s --set-as-default", op.PolicyARN, f))
			expr, err := jsonencodeExpr(docs[op.DocumentHash], "  ")
			if err != nil {
				return a, err
			}
			name, _ := policyNamePath(op.PolicyARN)
			fmt.Fprintf(&tf, "# In the aws_iam_policy that declares %s (%s):\n#   policy = %s\n\n", op.PolicyARN, name,
				strings.ReplaceAll(expr, "\n", "\n#   "))
		case igagov.OpDeletePolicyVersion:
			what := "the oldest non-default version"
			if op.Select == igagov.SelectAllNonDefault {
				what = "every non-default version"
			}
			cond := ""
			if op.IfVersionsAtLeast > 0 {
				cond = fmt.Sprintf(" (only if the policy has %d versions)", op.IfVersionsAtLeast)
			}
			a.CLI = append(a.CLI, fmt.Sprintf("# delete %s of %s%s: aws iam list-policy-versions --policy-arn %s, then aws iam delete-policy-version --policy-arn %s --version-id <id>",
				what, op.PolicyARN, cond, op.PolicyARN, op.PolicyARN))
		case igagov.OpTagPolicy:
			a.CLI = append(a.CLI, fmt.Sprintf("aws iam tag-policy --policy-arn %s --tags %s", op.PolicyARN, cliTags(sub(op.Tags))))
		case igagov.OpPutRolePermissionsBoundary:
			rn := op.RoleName
			if rn == "" {
				rn = roleNameOf(op.RoleARN)
			}
			a.CLI = append(a.CLI, fmt.Sprintf("aws iam put-role-permissions-boundary --role-name %s --permissions-boundary %s", rn, op.PolicyARN))
			fmt.Fprintf(&tf, "# In aws_iam_role %s:\n#   permissions_boundary = %s\n\n", q(rn), q(op.PolicyARN))
		case igagov.OpDeleteRolePermissionsBoundary:
			rn := op.RoleName
			if rn == "" {
				rn = roleNameOf(op.RoleARN)
			}
			a.CLI = append(a.CLI, fmt.Sprintf("aws iam delete-role-permissions-boundary --role-name %s", rn))
			fmt.Fprintf(&tf, "# In aws_iam_role %s: remove permissions_boundary\n\n", q(rn))
		case igagov.OpDeletePolicy:
			a.CLI = append(a.CLI, fmt.Sprintf("aws iam delete-policy --policy-arn %s", op.PolicyARN))
			fmt.Fprintf(&tf, "# Remove the aws_iam_policy that declares %s\n\n", op.PolicyARN)
		case igagov.OpCreateRole:
			name := roleNameOf(op.RoleARN)
			f := "trust-" + name + ".json"
			if d, ok := docs[op.TrustPolicyHash]; ok {
				a.Documents[f] = d
			}
			cmd := fmt.Sprintf("aws iam create-role --role-name %s --path %s --assume-role-policy-document file://%s", name, op.Path, f)
			if len(op.Tags) > 0 {
				cmd += " --tags " + cliTags(op.Tags)
			}
			a.CLI = append(a.CLI, cmd)
			fmt.Fprintf(&tf, "resource \"aws_iam_role\" %q {\n  name = %s\n  path = %s\n  # assume_role_policy: the source role's trust policy (%s)\n}\n\n",
				tfName(name), q(name), q(op.Path), op.TrustPolicyHash)
		case igagov.OpAttachRolePolicy:
			a.CLI = append(a.CLI, fmt.Sprintf("aws iam attach-role-policy --role-name %s --policy-arn %s", roleNameOf(op.RoleARN), op.PolicyARN))
		case igagov.OpPutRolePolicy:
			f := "inline-" + op.InlineName + ".json"
			if d, ok := docs[op.DocumentHash]; ok {
				a.Documents[f] = d
			}
			a.CLI = append(a.CLI, fmt.Sprintf("aws iam put-role-policy --role-name %s --policy-name %s --policy-document file://%s",
				roleNameOf(op.RoleARN), op.InlineName, f))
		case igagov.OpBindSubject:
			a.CLI = append(a.CLI, fmt.Sprintf("# move %s (%s) to %s: %s", op.SubjectARN, op.Binding, op.RoleARN, strings.Join(op.Steps, ", ")))
		case igagov.OpDeleteRole:
			cond := ""
			if op.OnlyIfUnused {
				cond = " (only if nothing else runs as it; otherwise keep the role)"
			}
			a.CLI = append(a.CLI, fmt.Sprintf("# delete %s%s: %s", op.RoleARN, cond, strings.Join(op.Steps, ", ")))
		case igagov.OpAddResourcePolicyPrincipal, igagov.OpAddTrustPolicyPrincipal:
			a.CLI = append(a.CLI, fmt.Sprintf("# add %s beside the source role in the policy of %s%s", op.Principal, op.ResourceARN, op.RoleARN))
		case igagov.OpRemoveResourcePolicyPrincipal, igagov.OpRemoveTrustPolicyPrincipal:
			a.CLI = append(a.CLI, fmt.Sprintf("# remove %s from the policy of %s%s", op.Principal, op.ResourceARN, op.RoleARN))
		}
	}
	for _, h := range []*string{p.DesiredDocumentHash} {
		if h != nil {
			if _, err := addDoc(*h); err != nil {
				return a, err
			}
		}
	}
	a.Terraform = tf.String()
	return a, nil
}
