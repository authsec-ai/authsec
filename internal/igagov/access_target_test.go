package igagov

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAWSAccessTargetS3(t *testing.T) {
	got, err := ParseAWSAccessTarget("arn:aws:s3:::reports-prod/2026/*", "invoices/")
	if err != nil {
		t.Fatal(err)
	}
	s, ok := got.(S3Target)
	if !ok || s.Bucket != "reports-prod" || s.Prefix != "invoices/" || got.Type() != AccessTypeS3Bucket ||
		got.ARN() != "arn:aws:s3:::reports-prod" || got.ARNAccount() != "" || got.ARNPartition() != "aws" {
		t.Fatalf("parsed %#v", got)
	}
	if _, err := ParseAWSAccessTarget("arn:aws:sqs:us-east-1:111122223333:queue", ""); !errors.Is(err, ErrAccessNotSupported) {
		t.Fatalf("an SQS ARN: %v, want ErrAccessNotSupported", err)
	}
	if got := AccessTypes(); len(got) == 0 || got[0] != AccessTypeS3Bucket {
		t.Fatalf("AccessTypes %v", got)
	}
}

// A "$" in a key prefix is written ${$}: "${" would start a policy variable,
// so a folder named a${aws:username}/ would match each caller's own name.
func TestS3PrefixDollarIsLiteral(t *testing.T) {
	tg, _ := ParseAWSAccessTarget("arn:aws:s3:::acme", "a${aws:username}/")
	end := AccessNoEnd
	doc, _, _, resources, err := AccessDocument(AccessEffectBlock, []string{AccessRead}, tg, nil, &end)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc), "${aws:username}") || !strings.Contains(string(doc), "a${$}{aws:username}/*") {
		t.Fatalf("document: %s", doc)
	}
	for _, r := range resources {
		if strings.Contains(r, "${aws") {
			t.Fatalf("resource %s", r)
		}
	}
	// Every list-guard fragment is escaped too ("a$" -> "a${$}").
	if !strings.Contains(string(doc), `"a${$}"`) {
		t.Fatalf("guard fragment not escaped: %s", doc)
	}
}
