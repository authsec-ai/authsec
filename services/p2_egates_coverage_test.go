package services

import (
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// §7.1 E9 ("coverage names the failed call"), P2-DECISIONS D-104, as pure
// logic: policy_documents' api and error_code are its FIRST failing call and
// AWS's code for it, taken from the fetch's own structured fields -- never
// from a reason's prose -- and nothing when no document failed on a call.
// End to end: tests/integration/p2_egates_failure_test.go (E9 b).
func TestEgatesPolicyDocumentsNamesTheFirstFailedCall(t *testing.T) {
	refused := func(name, api, code string) awsdiscovery.AttachedPolicy {
		return awsdiscovery.AttachedPolicy{Name: name, VersionID: "v1",
			FetchError: "fetch: refused", FetchAPI: api, FetchCode: code}
	}
	out := &PermissionSnapshot{}
	// A trust document that did not parse comes first and names no call; the
	// first document refused BY a call names the surface's; a later refusal
	// on another call does not replace it -- it is named in its own item.
	out.noteUnreadableItem(models.CoverageItem{Policy: "trust policy of R", Error: "parse: no Statement"})
	out.noteUnreadablePolicy(awsdiscovery.AttachedPolicy{Name: "Parsed", VersionID: "v2"}, "parse: malformed")
	out.noteUnreadablePolicy(refused("First", "iam:GetPolicyVersion", "AccessDenied"), "fetch: refused")
	out.noteUnreadablePolicy(refused("Second", "iam:GetPolicy", "Throttling"), "fetch: refused")
	cov := policyDocumentsSurface(out, 1)
	if cov.State != models.CloudCoveragePartial || cov.API != "iam:GetPolicyVersion" || cov.ErrorCode != "AccessDenied" {
		t.Errorf("policy_documents = %+v, want partial naming iam:GetPolicyVersion / AccessDenied, the first failed call", cov)
	}
	if len(cov.Items) != 4 || cov.Items[3] != (models.CoverageItem{Policy: "Second", Version: "v1", Error: "fetch: refused"}) {
		t.Errorf("items = %+v, want all four documents, each with its own reason", cov.Items)
	}

	// Nothing failed on a call -- every unreadable document was read and did
	// not parse: no call, no code, however the reasons are worded.
	parsed := &PermissionSnapshot{}
	parsed.noteUnreadablePolicy(awsdiscovery.AttachedPolicy{Name: "Parsed", VersionID: "v2"},
		"fetch: AWS returned AccessDenied for iam:GetPolicyVersion: prose, not a call")
	// A fetch failure that named no call (the listing omitted the policy)
	// names none either: unknown is said as unknown.
	parsed.noteUnreadablePolicy(awsdiscovery.AttachedPolicy{Name: "Absent", FetchError: "fetch: attached but absent"},
		"fetch: attached but absent")
	if cov := policyDocumentsSurface(parsed, 0); cov.API != "" || cov.ErrorCode != "" || len(cov.Items) != 2 {
		t.Errorf("no call failed: policy_documents = %+v, want no api or error_code, both documents listed", cov)
	}
}
