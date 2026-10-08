package iacpr

import (
	"fmt"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// Description is what a PR, an export and the policy detail say about a
// change (§8.11: the plain-language effect, the plan hash, and how AuthSec
// will recognise the applied result).
type Description struct {
	Title       string   `json:"title"`
	Effect      string   `json:"effect"`
	PlanHash    string   `json:"plan_hash"`
	Recognition []string `json:"recognition"`
	Body        string   `json:"body"`
}

// Describe describes a plan for a role.
func Describe(p igagov.Plan, role RoleTarget, ch *Change) Description {
	d := Description{PlanHash: p.PlanHash}
	removed := append([]string{}, p.Diff.NewlyExcluded...)
	restored := append([]string{}, p.Diff.NewlyUnexcluded...)
	sort.Strings(removed)
	sort.Strings(restored)
	switch p.Kind {
	case igagov.PlanApply:
		d.Title = fmt.Sprintf("AuthSec: restrict AWS services for %s", role.Name)
		d.Effect = fmt.Sprintf("Restricts these AWS services for this role: %s. Does not change actions or resources within kept services.",
			strings.Join(nonEmpty(removed), ", "))
	case igagov.PlanUndo:
		d.Title = fmt.Sprintf("AuthSec: undo the change to %s", role.Name)
		d.Effect = "Restores the boundary this role had before AuthSec's change."
	case igagov.PlanRemoveControl:
		d.Title = fmt.Sprintf("AuthSec: end AuthSec control of %s", role.Name)
		d.Effect = "Restores the boundary this role had before AuthSec's first change."
	case igagov.PlanSplit:
		d.Title = fmt.Sprintf("AuthSec: give %s its own role", subjectName(p))
		d.Effect = "Moves one workload to its own role with the source role's authorization unchanged (same trust policy, " +
			"managed policies by ARN, inline policy copies and boundary). No permission is removed for anyone."
	case igagov.PlanSplitRevert:
		d.Title = fmt.Sprintf("AuthSec: move %s back to its shared role", subjectName(p))
		d.Effect = "Moves the workload back to the shared role and removes the role the split added."
	}
	if len(restored) > 0 && p.Kind != igagov.PlanApply {
		d.Effect += " Services no longer excluded: " + strings.Join(restored, ", ") + "."
	}
	d.Recognition = recognition(p, role)
	var b strings.Builder
	b.WriteString(d.Effect + "\n\n")
	if ch != nil && len(ch.Summary) > 0 {
		b.WriteString("Changes:\n")
		for _, s := range ch.Summary {
			b.WriteString("- " + s + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("Merging is not applying: AuthSec waits for your pipeline to apply this change and recognises it in AWS by:\n")
	for _, r := range d.Recognition {
		b.WriteString("- " + r + "\n")
	}
	b.WriteString("\nPlan hash: `" + p.PlanHash + "`\n")
	b.WriteString("If the applied result differs from this change, AuthSec reports it as unexpected and does not treat it as verified.\n")
	d.Body = b.String()
	return d
}

func nonEmpty(s []string) []string {
	if len(s) == 0 {
		return []string{"(none)"}
	}
	return s
}

func subjectName(p igagov.Plan) string {
	if p.Diff.Split == nil {
		return "the workload"
	}
	a := p.Diff.Split.SubjectARN
	return a[strings.LastIndexAny(a, "/:")+1:]
}

// recognition lists the facts the verifier will read (§2.8 facts with their
// after values).
func recognition(p igagov.Plan, role RoleTarget) []string {
	var out []string
	out = append(out, "role "+role.ARN+" with RoleId "+role.RoleID)
	for _, f := range p.Facts {
		if !f.Changes() {
			continue
		}
		switch f.Kind {
		case igagov.FactRoleBoundary:
			out = append(out, "permissions boundary "+f.After)
		case igagov.FactPolicyDocument:
			if f.After == igagov.ValueAbsent {
				out = append(out, f.Subject+" deleted")
			} else {
				out = append(out, f.Subject+" default document hash "+f.After)
			}
		case igagov.FactBinding:
			out = append(out, f.Subject+" runs as "+f.After)
		case igagov.FactNewRole:
			if f.After == igagov.ValueAbsent {
				out = append(out, f.Subject+" deleted")
			} else {
				out = append(out, f.Subject+" with definition hash "+f.After)
			}
		}
	}
	return out
}
