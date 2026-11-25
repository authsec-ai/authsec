package services

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/models"
)

func TestDirectoryFromSCIMMapsManagerTypeAndActive(t *testing.T) {
	raw := `{"userName":"ravi","externalId":"00u1","active":false,"userType":"Employee",
	  "emails":[{"value":"Ravi@Corp.example","primary":true}],
	  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeType":"Contractor","manager":{"value":"00u9"}},
	  "urn:authsec:params:scim:schemas:extension:directory:1.0:User":{"leaveFrom":"2026-01-01T00:00:00Z"}}`
	var in models.SCIMCreateUserInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	d := DirectoryFromSCIM(in, uid)
	if d.Source != "scim" || d.ExternalID != "00u1" || *d.UserID != uid || *d.Active {
		t.Fatalf("core: %+v", d)
	}
	if *d.ManagerExternalID != "00u9" || *d.EmployeeType != "Contractor" || d.LeaveFrom == nil {
		t.Fatalf("extension: manager %v type %v leave %v", *d.ManagerExternalID, *d.EmployeeType, d.LeaveFrom)
	}
	if !IsContractorType(*d.EmployeeType) || IsContractorType("Employee") {
		t.Fatal("contractor type")
	}
	// No externalId: keyed by the user id.
	in.ExternalID = ""
	if d := DirectoryFromSCIM(in, uid); d.ExternalID != uid.String() {
		t.Fatalf("external id fallback: %s", d.ExternalID)
	}
}

func TestDirectoryPatchFromSCIM(t *testing.T) {
	uid := uuid.New()
	ops := []models.SCIMPatchOp{
		{Op: "replace", Path: "active", Value: false},
		{Op: "replace", Path: models.SCIMEnterpriseUserSchema + ":manager", Value: map[string]any{"value": "m-1"}},
		{Op: "add", Path: "", Value: map[string]any{"userType": "Vendor"}},
	}
	d, ok := DirectoryPatchFromSCIM(ops, "", uid)
	if !ok || *d.Active || *d.ManagerExternalID != "m-1" || *d.EmployeeType != "Vendor" || d.ExternalID != uid.String() {
		t.Fatalf("patch: %+v ok=%v", d, ok)
	}
	if _, ok := DirectoryPatchFromSCIM([]models.SCIMPatchOp{{Op: "replace", Path: "title", Value: "x"}}, "e", uid); ok {
		t.Fatal("a non-directory attribute touched the directory")
	}
	d, _ = DirectoryPatchFromSCIM([]models.SCIMPatchOp{{Op: "remove", Path: "manager"}}, "e", uid)
	if d.ManagerExternalID == nil || *d.ManagerExternalID != "" {
		t.Fatal("remove manager")
	}
}

func TestDirectoryStatusAndEntra(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	cases := []struct {
		active, deleted bool
		from, to        *time.Time
		want            string
	}{
		{true, false, nil, nil, "active"},
		{false, false, nil, nil, "left"},
		{true, true, nil, nil, "left"},
		{false, false, &past, &future, "leave"},
		{true, false, &future, nil, "active"},
		{false, false, &past, &past, "left"},
	}
	for i, c := range cases {
		if got := directoryStatus(c.active, c.deleted, c.from, c.to, now); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
	enabled := true
	u := azure.DirectoryPerson{ID: "e1", Mail: "a@b", AccountEnabled: &enabled, EmployeeType: "Contractor", EmployeeLeaveDateTime: &past}
	u.Manager = &struct {
		ID string `json:"id"`
	}{ID: "m1"}
	d := DirectoryFromEntra(u)
	if d.Source != "entra" || *d.Active || *d.ManagerExternalID != "m1" || *d.EmployeeType != "Contractor" {
		t.Fatalf("entra: %+v", d)
	}
}

func TestClassificationTagsAndLowering(t *testing.T) {
	tc, ok := ClassificationFromTags(map[string]string{"AuthSec:Sensitivity": "High", "authsec:crown-jewel": "true",
		"authsec:data-category": "PII", "authsec:residency": "EU", "env": "prod"})
	if !ok || tc.Sensitivity != "high" || !tc.CrownJewel || tc.DataCategory != "pii" || tc.Residency != "eu" ||
		tc.Reason != "Resource tags: authsec:crown-jewel=true, authsec:data-category=pii, authsec:residency=eu, authsec:sensitivity=high" {
		t.Fatalf("tags: %+v", tc)
	}
	if _, ok := ClassificationFromTags(map[string]string{"authsec:sensitivity": "extreme"}); ok {
		t.Fatal("an unreadable tag was taken")
	}
	r := models.CloudResource{Sensitivity: "low", SensitivitySource: models.SensitivityFromHeuristic}
	ApplyTagClassification(&r, map[string]string{"authsec:sensitivity": "medium"})
	if r.Sensitivity != models.SensitivityMedium || r.SensitivitySource != models.SensitivityFromProvider {
		t.Fatalf("applied: %+v", r)
	}
	cur := ResourceClassification{Sensitivity: "high", CrownJewel: true, DataCategory: "pii", Residency: "eu"}
	for _, c := range []struct {
		next  ResourceClassification
		lower bool
	}{
		{ResourceClassification{"high", true, "pii", "eu"}, false},
		{ResourceClassification{"med", true, "pii", "eu"}, true},
		{ResourceClassification{"high", false, "pii", "eu"}, true},
		{ResourceClassification{"high", true, "", "eu"}, true},
		{ResourceClassification{"high", true, "pii", "us"}, true},
	} {
		if got := IsClassificationLowering(cur, c.next); got != c.lower {
			t.Errorf("%+v: lowering %v", c.next, got)
		}
	}
	if IsClassificationLowering(ResourceClassification{Sensitivity: "low"}, ResourceClassification{Sensitivity: "high", CrownJewel: true, DataCategory: "pii"}) {
		t.Fatal("a raise counted as lowering")
	}
	if _, err := (MacieClassificationSource{}).Classifications(context.Background(), uuid.Nil, uuid.Nil); err == nil {
		t.Fatal("macie stub must say it is unavailable")
	}
}

func TestAWSAgentInstanceFromAttrs(t *testing.T) {
	gid, ident := uuid.New(), uuid.New()
	attrs, _ := json.Marshal(models.AWSWorkloadAttrs{ArtifactDigest: "lambda-sha256:abc", ArtifactVersion: "1",
		Deployer: "arn:aws:iam::1:role/ci", FoundationModel: "anthropic.claude"})
	w := &arWorkload{NativeID: "arn:fn", RuntimeKind: "lambda_function", Region: "eu-west-1", Attrs: attrs, GraphID: &gid, IdentityID: &ident}
	o := awsAgentInstance(w, time.Now())
	if o.SourceTable != "iga_workload" || o.SourceID != gid.String() || o.ArtifactDigest != "lambda-sha256:abc" ||
		o.Deployer != "arn:aws:iam::1:role/ci" || o.Model != "anthropic.claude" || *o.CloudIdentityID != ident || o.Environment != "eu-west-1" {
		t.Fatalf("instance: %+v", o)
	}
	md, _ := json.Marshal(map[string]any{"image_digest": "sha256:feed", "namespace": "agents", "deployer": "system:serviceaccount:ci"})
	if s, ok := sightingInstance(&models.DiscoveredAgent{ID: uuid.New(), Source: "k8s_webhook", Fingerprint: "fp", Metadata: md}); !ok ||
		s.ArtifactDigest != "sha256:feed" || s.Environment != "agents" || s.Deployer != "system:serviceaccount:ci" {
		t.Fatalf("sighting instance: %+v %v", s, ok)
	}
	if _, ok := sightingInstance(&models.DiscoveredAgent{Metadata: []byte(`{}`)}); ok {
		t.Fatal("a sighting with no artifact made an instance")
	}
}
