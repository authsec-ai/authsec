package igagov

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// compileGoldenCases compiles one plan of every shape from fixed inputs. The
// whole plan record (columns, ops in execution order, diff with facts,
// archived documents) is committed as canonical JSON under
// testdata/golden/plan.*.json, its plan_hash and material_hash in
// testdata/compile_golden_hashes.json, and the boundary documents it
// installs under testdata/golden/document.*.json (content-addressed: check
// with sha256sum). Any change to a plan's shape, op order or hash fails here.
func compileGoldenCases(t *testing.T) (plans map[string]Plan, docs map[string][]byte) {
	t.Helper()
	plans, docs = map[string]Plan{}, map[string][]byte{}
	add := func(name string, p Plan) {
		if err := p.CheckStorable(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		plans[name] = p
	}

	s := newSim()
	s.addRole(baseRole())
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2", "sqs"))
	add("apply.none_to_authsec", tp.Apply)
	add("undo.none_to_authsec", *tp.Undo)
	docs["authsec_boundary.ec2_sqs"] = []byte(tp.Apply.Documents[0].Canonical)

	s.run(t, roleID, tp.Apply, 0, 2, planDocs(tp.Apply))
	b := s.addRole(roleB())
	b.BoundaryARN = authsecARN()
	rp, err := CompileRoleOnlyRecovery(RecoveryInput{Control: testControl(), Undo: *tp.Undo, UndoneDeploymentID: depID,
		Live: s.read(roleID), Evidence: evidenceFor(t, []string{"ec2", "sqs"}, evOpts{})})
	if err != nil {
		t.Fatal(err)
	}
	add("undo.role_only_detach", rp)
	rc, err := CompileRemoveControl(RemoveControlInput{Control: testControl(), Delivery: DeliveryDirect, Live: s.read(roleID),
		LastDeployed: BoundaryRef{authsecARN(), deref(tp.Apply.DesiredDocumentHash)}, Evidence: evidenceFor(t, []string{"ec2", "sqs"}, evOpts{}),
		ExcludedServices: []string{"ec2", "sqs"}})
	if err != nil {
		t.Fatal(err)
	}
	add("remove_control.retain_shared", rc)

	as, _ := authsecWorld(t, []string{"sqs"}, 5)
	av := mustCompile(t, targetIn(t, as, DeliveryDirect, "sns", "sqs"))
	add("apply.authsec_version", av.Apply)
	add("undo.authsec_version", *av.Undo)

	cs := customerWorld(false)
	ci := mustCompile(t, targetIn(t, cs, DeliveryIaCPR, "sqs"))
	add("apply.customer_in_place", ci.Apply)
	add("undo.customer_in_place", *ci.Undo)
	for _, d := range ci.Apply.Documents {
		if d.Hash == deref(ci.Apply.DesiredDocumentHash) {
			docs["customer_narrowed.sqs"] = []byte(d.Canonical)
		}
	}

	ss := customerWorld(true)
	sc := mustCompile(t, targetIn(t, ss, DeliveryIaCPR, "sqs"))
	add("apply.customer_split", sc.Apply)
	add("undo.customer_split", *sc.Undo)

	src := baseRole()
	ds := newSim()
	ds.addRole(src)
	lr := ds.read(roleID)
	newARN := "arn:aws:iam::" + acct + ":role/refund-reconciler-role"
	lr.Roles = map[string]*LiveRole{newARN: nil}
	sp, err := CompileSplit(SplitInput{Control: testControl(), Live: lr, Evidence: evidenceFor(t, nil, evOpts{}),
		Intent: DedicatedIdentityIntent{Kind: IntentDedicatedIdentity, Source: Subject{IdentityAccountID: identityID, RoleID: roleID, AccountID: acct},
			Workload: DedicatedWorkload{WorkloadID: identityID, BindingKind: BindingLambdaRole, BindingRef: "arn:aws:lambda:us-east-1:" + acct + ":function:refund"},
			NewRole: NewRole{Name: "refund-reconciler-role", Path: "/", TrustPolicyHash: src.TrustPolicyHash, ManagedPolicyARNs: []string{src.ManagedPolicies[0].Ref},
				InlinePolicies: []InlinePolicyRef{{Name: "refund-inline", DocumentHash: src.InlinePolicies[0].DocumentHash}}},
			Delivery: DeliveryIaCPR},
		SubjectKind: SubjectLambdaFunction, SubjectARN: "arn:aws:lambda:us-east-1:" + acct + ":function:refund", Aliases: []string{"live"},
		AccountServices: []string{"lambda"}, MigrationEvidenceAvailable: true})
	if err != nil {
		t.Fatal(err)
	}
	add("split.lambda", sp.Split)
	add("split_revert.lambda", *sp.Revert)
	return plans, docs
}

func TestGoldenPlans(t *testing.T) {
	plans, docs := compileGoldenCases(t)
	dir := filepath.Join("testdata", "golden")
	hashFile := filepath.Join("testdata", "compile_golden_hashes.json")
	got := map[string]string{}
	texts := map[string][]byte{}
	for name, p := range plans {
		c, err := CanonicalizeValue(p)
		if err != nil {
			t.Fatal(err)
		}
		texts["plan."+name] = c
		got["plan."+name+".plan_hash"] = p.PlanHash
		got["plan."+name+".material_hash"] = p.MaterialHash
		got["plan."+name+".precondition_hash"] = p.PreconditionHash
	}
	for name, d := range docs {
		texts["document."+name] = d
		got["document."+name] = ContentHash(d)
	}
	if *updateGolden {
		for name, c := range texts {
			if err := os.WriteFile(filepath.Join(dir, name+".json"), c, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		js, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(hashFile, append(js, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(hashFile)
	if err != nil {
		t.Fatalf("%v (run go test -run TestGoldenPlans -update once)", err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(got) {
		t.Fatalf("golden file has %d entries, test has %d", len(want), len(got))
	}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if want[n] != got[n] {
			t.Errorf("%s: %s, golden %s", n, got[n], want[n])
		}
	}
	for name, c := range texts {
		b, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != string(c) {
			t.Errorf("%s: canonical text differs from golden", name)
		}
	}
	// The committed documents are what the hashes say (sha256sum-checkable).
	for name := range docs {
		b, _ := os.ReadFile(filepath.Join(dir, "document."+name+".json"))
		if ContentHash(b) != got["document."+name] {
			t.Errorf("document.%s: content hash is not sha256 of the file", name)
		}
	}
}
