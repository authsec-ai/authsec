package services

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// S3a (T3.3, P2-DECISIONS D-71): the coverage entries collection stamps, as
// pure logic. No database: these functions only shape what the scanners
// already decided. The end-to-end behaviour is proven in
// tests/integration/p2_s3a_authdetails_test.go.

// policy_documents lists every unreadable document as an item, and BOTH the
// items and the prose stop at models.CoverageItemLimit, saying so: the count
// is always the full one.
func TestS3aPolicyDocumentsItemsAreBounded(t *testing.T) {
	out := &PermissionSnapshot{PoliciesWritten: 150}
	for i := 0; i < models.CoverageItemLimit+1; i++ {
		out.noteUnreadable(fmt.Sprintf("Broken%03d", i), "v1", "parse: malformed")
	}
	// Recorded twice (two holders of one managed policy): still one document.
	out.noteUnreadable("Broken000", "v1", "parse: malformed")

	cov := policyDocumentsSurface(out, 7)
	if cov.State != models.CloudCoveragePartial || cov.Count != 157 {
		t.Errorf("state/count = %s/%d, want partial/157 (policies + trust documents examined)", cov.State, cov.Count)
	}
	if len(cov.Items) != models.CoverageItemLimit || !cov.Truncated {
		t.Fatalf("items = %d truncated %v, want %d and truncated", len(cov.Items), cov.Truncated, models.CoverageItemLimit)
	}
	if cov.Items[0] != (models.CoverageItem{Policy: "Broken000", Version: "v1", Error: "parse: malformed"}) {
		t.Errorf("first item = %+v", cov.Items[0])
	}
	if !strings.HasPrefix(cov.Error, "101 policies could not be read: Broken000 v1 (parse: malformed); ") ||
		!strings.HasSuffix(cov.Error, "Broken099 v1 (parse: malformed); and 1 more") ||
		strings.Contains(cov.Error, "Broken100") {
		t.Errorf("error = %q, want the full count, the first %d named, and the rest counted", cov.Error, models.CoverageItemLimit)
	}

	// At the limit: everything listed, nothing truncated.
	few := &PermissionSnapshot{}
	few.noteUnreadable("TicketRead", "v3", "fetch: AWS returned AccessDenied for iam:GetPolicyVersion: no")
	few.noteUnreadableItem(models.CoverageItem{Policy: "trust policy of SharedToolRole", Error: "parse: no Statement"})
	cov = policyDocumentsSurface(few, 1)
	if len(cov.Items) != 2 || cov.Truncated ||
		cov.Error != "2 policies could not be read: TicketRead v3 (fetch: AWS returned AccessDenied for "+
			"iam:GetPolicyVersion: no); trust policy of SharedToolRole (parse: no Statement)" {
		t.Errorf("coverage = %+v", cov)
	}
	// Only legacy parse failures (no document named): partial, no items.
	if cov := policyDocumentsSurface(&PermissionSnapshot{ParseFailures: 1}, 1); len(cov.Items) != 0 ||
		cov.Truncated || cov.State != models.CloudCoveragePartial {
		t.Errorf("unnamed failure = %+v, want partial with no items", cov)
	}
}

// surfaceResult stamps the failed call and AWS's code when the error names
// them, and nothing when it does not: never inferred from the message.
func TestS3aSurfaceResultStampsTheCall(t *testing.T) {
	named := fmt.Errorf("scan: %w", &awsdiscovery.APICallError{
		API: "iam:GetAccountAuthorizationDetails (Users)", Code: "AccessDenied", Message: "no",
	})
	cov := surfaceResult(3, named)
	if cov.State != models.CloudCoverageDenied || cov.Count != 3 ||
		cov.API != "iam:GetAccountAuthorizationDetails (Users)" || cov.ErrorCode != "AccessDenied" {
		t.Errorf("named failure = %+v", cov)
	}
	// Prose that LOOKS like it names a call is not a call.
	cov = surfaceResult(0, errors.New("AWS returned AccessDenied for iam:ListRoles: no"))
	if cov.State != models.CloudCoverageDenied || cov.API != "" || cov.ErrorCode != "" {
		t.Errorf("unnamed failure = %+v, want no api or error_code", cov)
	}
	if cov := surfaceResult(5, nil); cov.State != models.CloudCoverageReached || cov.Count != 5 ||
		cov.Error != "" || cov.API != "" || cov.ErrorCode != "" {
		t.Errorf("reached = %+v", cov)
	}
}
