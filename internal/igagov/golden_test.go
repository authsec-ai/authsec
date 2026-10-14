package igagov

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden and testdata/golden_hashes.json")

// specBoundary is §3.2's R1a boundary document.
const specBoundary = `{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AuthSecAllowAllExceptRemoved",
    "Effect": "Allow",
    "NotAction": ["ec2:*", "sqs:*"],
    "Resource": "*"
  }]
}`

type goldenCase struct {
	canonical []byte // nil when the hash is not over one canonical text
	hash      string
}

func goldenCases(t *testing.T) map[string]goldenCase {
	t.Helper()
	out := map[string]goldenCase{}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, raw := range map[string]string{"intent.right_size_services": specIntent,
		"intent.remove_control": specRemoveControl, "intent.dedicated_identity": specDedicated} {
		c, err := Canonicalize([]byte(raw))
		must(err)
		h, err := IntentHash([]byte(raw))
		must(err)
		out[name] = goldenCase{c, h}
	}
	c, h, err := CanonicalDocument(specBoundary)
	must(err)
	out["document.boundary_example"] = goldenCase{c, h}

	fp, err := Fingerprint(KindUnusedService, roleID, "sqs")
	must(err)
	out["fingerprint.unused_service.sqs"] = goldenCase{nil, fp}

	b, err := BuildBundle(bundleInput(t), DefaultTrustRules())
	must(err)
	out["bundle.trusted_example"] = goldenCase{b.Canonical, b.Hash}

	im := Impact{Consumers: []ImpactConsumer{{wl1, RelExecutesAs}}, OwnerUserIDs: []string{"u1"},
		Removed: []ImpactService{{"sqs", RemoveNoAttempt}}, Retained: []ImpactService{{"s3", RetainObserved}, {"logs", RetainDependency}},
		StatementRevisions: []string{"ha", "hb"}, Routes: []Route{}}
	ic, err := CanonicalizeValue(im.Normalized())
	must(err)
	ih, err := ImpactHash(im)
	must(err)
	out["impact.example"] = goldenCase{ic, ih}

	arn, doc := "arn:aws:iam::"+acct+":policy/authsec/AuthSecBoundary-"+roleID, out["document.boundary_example"].hash
	st := ArtifactStateFacts{RoleID: roleID, BoundaryARN: &arn, BoundaryDocumentHash: &doc,
		AttachmentSet: []AttachedEntity{{Kind: "role", ID: roleID, Name: roleName, Usage: UsageBoundary}}}
	sh, err := StatePreconditionHash(st)
	must(err)
	sc, err := CanonicalizeValue(struct {
		ArtifactState ArtifactStateFacts `json:"artifact_state"`
	}{st.Normalized()})
	must(err)
	out["precondition.state_only"] = goldenCase{sc, sh}

	none := ArtifactStateFacts{RoleID: roleID}
	ap := ApplyPrecondition{ArtifactState: none, RoleARN: roleARN, RolePath: "/app/", ProtectionTags: map[string]string{},
		ManagedPolicies: []PolicyRef{{Ref: "arn:aws:iam::" + acct + ":policy/RefundAccess", DocumentHash: doc}}, InlinePolicies: []PolicyRef{}}
	apc, err := ap.Canonical()
	must(err)
	aph, err := ApplyPreconditionHash(ap)
	must(err)
	out["precondition.apply"] = goldenCase{apc, aph}

	p := samplePlanInput()
	p.PreconditionHash = aph
	ph, err := PlanHash(p)
	must(err)
	out["plan.example"] = goldenCase{nil, ph}
	mh, err := MaterialHash(MaterialHashInput{Plan: p, ImpactHash: ih, Gaps: []GapRef{}})
	must(err)
	out["material.example"] = goldenCase{nil, mh}

	g := Gap{Kind: GapUnanalysedForm, Key: "unanalysed_form:ecr_repository", Service: "ecr", Form: "ecr_repository", Reason: "form_not_collected"}
	gc, err := CanonicalizeValue(g)
	must(err)
	gh, err := GapHash(g)
	must(err)
	out["gap.unanalysed_form"] = goldenCase{gc, gh}
	return out
}

// TestGoldenHashes pins every hash definition: a change to canonicalisation,
// a domain tag, a field order or a fact layout fails here. Canonical texts
// are committed beside the hashes so the content hashes can be checked with
// any sha256 tool (sha256sum testdata/golden/document.boundary_example.json).
func TestGoldenHashes(t *testing.T) {
	cases := goldenCases(t)
	dir := filepath.Join("testdata", "golden")
	hashFile := filepath.Join("testdata", "golden_hashes.json")
	if *updateGolden {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		hashes := map[string]string{}
		for name, c := range cases {
			hashes[name] = c.hash
			if c.canonical != nil {
				if err := os.WriteFile(filepath.Join(dir, name+".json"), c.canonical, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		js, _ := json.MarshalIndent(hashes, "", "  ")
		if err := os.WriteFile(hashFile, append(js, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(hashFile)
	if err != nil {
		t.Fatalf("%v (run go test -run TestGoldenHashes -update once)", err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(want) != len(cases) {
		t.Fatalf("golden file has %d entries, test has %d", len(want), len(cases))
	}
	for _, n := range names {
		c := cases[n]
		if want[n] != c.hash {
			t.Errorf("%s: hash %s, golden %s", n, c.hash, want[n])
		}
		if c.canonical != nil {
			b, err := os.ReadFile(filepath.Join(dir, n+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != string(c.canonical) {
				t.Errorf("%s: canonical text differs from golden", n)
			}
			// Content hashes are plain sha256 of the file; tagged hashes
			// are sha256(domain ␟ file).
			if strings.HasPrefix(n, "document.") || strings.HasPrefix(n, "bundle.") {
				if ContentHash(b) != c.hash {
					t.Errorf("%s: content hash is not sha256 of the canonical file", n)
				}
			}
		}
	}
}
