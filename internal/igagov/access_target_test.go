package igagov

import (
	"errors"
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
