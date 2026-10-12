package igagov

import "testing"

// Review P1-6: a not_collected row for an enabled region outside the region
// list the caller passes is not_analysed, never "no route"; a scan that did
// not establish the enabled regions leaves every regional form not_analysed;
// the summaries and the first-attachment proof agree.
func TestP3CovUnselectedRegionRowsAreNotAnalysed(t *testing.T) {
	complete := func(region string) []CoverageRow {
		var rows []CoverageRow
		for _, f := range AllForms() {
			if f.State != FormCollected {
				continue
			}
			r := region
			if f.Scope == ScopeAccount {
				r = "us-east-1"
			}
			rows = append(rows, CoverageRow{Form: f.Name, Region: r, State: CoverageComplete})
		}
		return rows
	}
	role := RoleRef{RoleID: "AROAX", ARN: "arn:aws:iam::111122223333:role/x", AccountID: "111122223333"}
	selected := []string{"us-east-1"}

	full := &ResourcePolicyEvidence{Coverage: complete("us-east-1")}
	if ra := AnalyzeRoutes("sqs", role, full, selected); ra.State != RouteStateNoneObserved || ra.Usage != RouteUsageNoneObserved {
		t.Fatalf("complete evidence: %+v", ra)
	}
	if s := SummarizeCoverage(full, selected); s != CoverageComplete {
		t.Fatalf("complete evidence summarised %s", s)
	}

	// The collector's not_collected row for enabled-but-unselected eu-west-1.
	unsel := &ResourcePolicyEvidence{Coverage: append(complete("us-east-1"),
		CoverageRow{Form: "sqs_queue", Region: "eu-west-1", State: CoverageNotCollected, Reason: "region enabled in the account but not selected on the connector"})}
	ra := AnalyzeRoutes("sqs", role, unsel, selected)
	found := false
	for _, r := range ra.Routes {
		found = found || (r.Form == "sqs_queue" && r.Region == "eu-west-1" && r.Effect == RouteEffectNotAnalysed)
	}
	if !found || ra.State != RouteStateNotAnalysed || ra.Usage != RouteUsageConfirmRequired {
		t.Fatalf("unselected region: %+v, want sqs_queue/eu-west-1 not_analysed", ra)
	}
	if s := SummarizeCoverage(unsel, selected); s != CoveragePartial {
		t.Fatalf("unselected region summarised %s, want partial", s)
	}
	p := ProveFirstAttachment(role, "run", unsel, selected, []string{"sqs"}, nil)
	if !p.Blocked() || len(p.Incomplete) != 1 || p.Incomplete[0].Region != "eu-west-1" {
		t.Fatalf("proof %+v, want blocked by sqs_queue in eu-west-1", p)
	}

	// Enabled regions not established.
	unknown := &ResourcePolicyEvidence{Coverage: complete("us-east-1"), EnabledRegionsUnknown: true}
	ra = AnalyzeRoutes("sqs", role, unknown, selected)
	if ra.State != RouteStateNotAnalysed || len(ra.Routes) != 1 || ra.Routes[0].Reason != ReasonEnabledRegionsUnknown {
		t.Fatalf("unknown enabled regions: %+v", ra)
	}
	if s := SummarizeCoverage(unknown, selected); s != CoveragePartial {
		t.Fatalf("unknown enabled regions summarised %s", s)
	}
	if p := ProveFirstAttachment(role, "run", unknown, selected, []string{"sqs"}, nil); !p.Blocked() {
		t.Fatal("unknown enabled regions: the first attachment was not refused")
	}
	// Account-scoped forms are read once: the unknown flag does not touch them.
	for _, r := range AnalyzeRoutes("s3", role, unknown, selected).Routes {
		if r.Form == "s3_bucket" || r.Form == "s3_multi_region_access_point" {
			t.Fatalf("account-scoped form %s not_analysed by the unknown regions", r.Form)
		}
	}
}
