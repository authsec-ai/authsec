package integration

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Ticket [2]'s resource-typing path, against a real database.
//
// Every existing fixture (populatedIAM, and the live AWS sandbox account used
// to manually verify tickets [1]/[2]) happens to only use "*" or partial-
// wildcard resources ("arn:aws:s3:::reports/*"), which ClassifyResourceScope
// deliberately treats as account_wide/prefix and never types. That left the
// one branch that actually calls TypeResourceARN -- a statement naming a bare,
// concrete ARN -- with no coverage anywhere. This file closes that gap.

const dataReaderRoleARN = "arn:aws:iam::429418377036:role/data-reader"

// iamWithConcreteResourceARNs is a one-role account whose inline policy names
// two bare ARNs (no wildcard): an S3 bucket and a DynamoDB table. That is the
// only shape ClassifyResourceScope resolves to scope_kind "resource" and hands
// to TypeResourceARN.
func iamWithConcreteResourceARNs() *fakeIAM {
	f := newFakeIAM()

	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	f.roles = []iamtypes.Role{{
		Arn: aws.String(dataReaderRoleARN), RoleName: aws.String("data-reader"),
		RoleId: aws.String("AROAEXAMPLEDATA"), Path: aws.String("/"),
		CreateDate:               ago(10 * 24 * time.Hour),
		AssumeRolePolicyDocument: aws.String(url.QueryEscape(trust)),
	}}

	f.inlineRolePolicies["data-reader"] = map[string]string{
		"read-specific-resources": `{"Version":"2012-10-17","Statement":[` +
			`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::authsec-livecheck-reports"},` +
			`{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"arn:aws:dynamodb:us-east-1:429418377036:table/AuditLog"}` +
			`]}`,
	}
	return f
}

func cleanPermissionTables(t *testing.T, db *gorm.DB, ws uuid.UUID) {
	t.Helper()
	db.Exec(`DELETE FROM cloud_permission WHERE workspace_id = ?`, ws)
	db.Exec(`DELETE FROM cloud_resource WHERE workspace_id = ?`, ws)
	db.Exec(`DELETE FROM cloud_assume_edge WHERE workspace_id = ?`, ws)
	cleanIdentities(t, db, ws)
}

func TestPermissionScanTypesConcreteResourceARNs(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-permission-resource-typing")
	defer cleanPermissionTables(t, db, ws)

	fake := iamWithConcreteResourceARNs()
	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	iamScanner := services.NewAWSIAMScanner(db, svc).WithIAMAPI(fake)
	snap, err := iamScanner.Scan(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("ticket [1] scan: %v", err)
	}

	permScanner := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(fake)
	permSnap, err := permScanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("ticket [2] scan: %v", err)
	}
	if permSnap.ResourcesWritten != 2 {
		t.Fatalf("expected 2 resources typed (one s3 bucket, one dynamodb table), got %d",
			permSnap.ResourcesWritten)
	}
	t.Logf("PASS: %d concrete resources typed and written", permSnap.ResourcesWritten)

	grants := repositories.NewCloudPermissionRepository(db)
	resources, err := grants.ListResources(ws, nil)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 cloud_resource rows, got %d", len(resources))
	}

	byKind := map[string]models.CloudResource{}
	for _, r := range resources {
		byKind[r.Kind] = r
	}

	bucket, ok := byKind["s3_bucket"]
	if !ok {
		t.Fatal("no s3_bucket resource was typed")
	}
	if bucket.Name != "authsec-livecheck-reports" {
		t.Fatalf("wrong bucket name, got %q", bucket.Name)
	}
	if bucket.NativeID != "arn:aws:s3:::authsec-livecheck-reports" {
		t.Fatalf("native_id must be the ARN verbatim, got %q", bucket.NativeID)
	}
	t.Log("PASS: S3 ARN typed as s3_bucket with the bucket name extracted")

	table, ok := byKind["dynamodb_table"]
	if !ok {
		t.Fatal("no dynamodb_table resource was typed")
	}
	if table.Name != "AuditLog" {
		t.Fatalf("wrong table name, got %q", table.Name)
	}
	t.Log("PASS: DynamoDB ARN typed as dynamodb_table with the table name extracted")

	// Every cloud_permission row from this statement must carry the resource it
	// was typed from -- ClassifyResourceScope returning a concrete resource is
	// the one case where resource_id must NOT be nil.
	perms, err := grants.ListPermissions(ws, nil)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	resourceScoped := 0
	for _, p := range perms {
		if p.ScopeKind == "resource" {
			resourceScoped++
			if p.ResourceID == nil {
				t.Fatalf("a resource-scoped permission (%s) must have a resource_id", p.NativeID)
			}
		}
	}
	if resourceScoped != 2 {
		t.Fatalf("expected 2 resource-scoped permissions, got %d", resourceScoped)
	}
	t.Log("PASS: both resource-scoped permissions reference their typed resource")
}
