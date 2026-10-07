package igagov

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Property tests over generated inputs (fixed seeds, so failures replay).

var nsPool = []string{"ec2", "sqs", "sns", "dynamodb", "glue", "kinesis", "logs", "ecr", "kms", "secretsmanager",
	"ssm", "xray", "bedrock", "lambda", "states", "athena", "rds", "ses"}

func pick(r *rand.Rand, n int, pool []string) []string {
	perm := r.Perm(len(pool))
	out := []string{}
	for _, i := range perm[:n] {
		out = append(out, pool[i])
	}
	return sortedUnique(out)
}

// The AuthSec boundary never excludes a retained service or a dependency of
// the workload context, and excludes every removed service; a removal that
// is a dependency makes the plan ineligible instead (§3.4 (1), §3.7).
func TestProperty_BoundaryNeverExcludesRetainedOrDependency(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	ctxPool := []DependencyContext{{Context: CtxLambdaExecution, TracingActive: true}, {Context: CtxECSTaskExecution, ReferencesSecrets: true},
		{Context: CtxBedrockAgent}, {Context: CtxKMSViaService}, {Context: CtxEC2InstanceRole}}
	for i := 0; i < 300; i++ {
		services := pick(r, 2+r.Intn(8), nsPool)
		cut := 1 + r.Intn(len(services)-1)
		remove, retainSvcs := services[:cut], services[cut:]
		var retain []RetainEntry
		for _, s := range retainSvcs {
			retain = append(retain, RetainEntry{Service: s, Basis: RetainOwner, Reason: "needed", ReviewBy: "2027-01-15"})
		}
		ctxs := []DependencyContext{ctxPool[r.Intn(len(ctxPool))]}
		s := newSim()
		s.addRole(baseRole())
		in := targetIn(t, s, DeliveryDirect, remove...)
		in.Intent = intentFor(DeliveryDirect, remove, retain...)
		in.DependencyContexts = ctxs
		p := mustCompile(t, in).Apply
		deps := Dependencies(ctxs)
		depRemoved := false
		for _, d := range deps {
			for _, rm := range remove {
				depRemoved = depRemoved || d.Service == rm
			}
		}
		if depRemoved {
			if p.Eligible() || !hasRefusal(p, RefuseRemovalIsDependency) {
				t.Fatalf("case %d: removing a dependency must be refused: %v %v", i, remove, ctxs)
			}
			continue
		}
		if !p.Eligible() {
			t.Fatalf("case %d: %v", i, p.Refusals)
		}
		doc, err := DecodePolicyDocument(p.Documents[0].Canonical)
		if err != nil {
			t.Fatal(err)
		}
		for _, sv := range append(append([]string{"s3"}, retainSvcs...), func() []string {
			var o []string
			for _, d := range deps {
				o = append(o, d.Service)
			}
			return o
		}()...) {
			if BoundaryExcludes(doc, sv) {
				t.Fatalf("case %d: boundary excludes kept service %s", i, sv)
			}
		}
		for _, rm := range remove {
			if !BoundaryExcludes(doc, rm) {
				t.Fatalf("case %d: boundary does not exclude %s", i, rm)
			}
		}
	}
}

type startState int

const (
	startNone startState = iota
	startAuthSec
	startCustomerExclusive
	startCustomerShared
)

func worldFor(t testing.TB, st startState, r *rand.Rand) (*simAccount, string) {
	switch st {
	case startNone:
		s := newSim()
		s.addRole(baseRole())
		return s, DeliveryDirect
	case startAuthSec:
		s, _ := authsecWorld(t, pick(r, 1+r.Intn(2), []string{"sqs", "sns", "kinesis"}), 1+r.Intn(5))
		return s, DeliveryDirect
	case startCustomerExclusive:
		return customerWorld(false), []string{DeliveryIaCPR, DeliveryExport}[r.Intn(2)]
	default:
		s := customerWorld(true)
		if r.Intn(2) == 0 {
			s.policies[teamBoundaryARN].permUsers = []AttachedEntity{{Kind: "group", ID: "AGPAEXAMPLE", Name: "ops", Usage: UsagePermissions}}
		}
		return s, []string{DeliveryIaCPR, DeliveryExport}[r.Intn(2)]
	}
}

// undo(apply(x)) restores x: the role's artifact_state and every policy's
// document and users; at every prefix the classifier walks before →
// intermediate → after for the apply and after → … → before for the undo.
func TestProperty_UndoOfApplyRestoresState(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	for i := 0; i < 200; i++ {
		st := startState(i % 4)
		s, delivery := worldFor(t, st, r)
		remove := pick(r, 1+r.Intn(3), []string{"sqs", "sns", "ec2", "kinesis"})
		tp := mustCompile(t, targetIn(t, s, delivery, remove...))
		if !tp.Apply.Eligible() {
			t.Fatalf("case %d (%d): %v", i, st, tp.Apply.Refusals)
		}
		ap, u := tp.Apply, *tp.Undo
		docs := planDocs(ap, u)
		x := s.snapshot()
		xs, _ := ArtifactState(s.read(roleID))
		visible := func(o Op) bool {
			switch o.Op {
			case OpCreatePolicy, OpCreatePolicyVersion, OpDeletePolicy, OpPutRolePermissionsBoundary, OpDeleteRolePermissionsBoundary:
				return true
			}
			return false
		}
		total := 0
		for _, o := range ap.Ops {
			if visible(o) {
				total++
			}
		}
		done := 0
		for k := 0; k <= len(ap.Ops); k++ {
			c := classify(t, s, ap)
			want := ClassIntermediate
			switch {
			case done == total:
				want = ClassAfter
			case done == 0:
				want = ClassBefore
			}
			if c.Class != want {
				t.Fatalf("case %d apply prefix %d/%d: %+v", i, k, len(ap.Ops), c)
			}
			if ap.Delivery == DeliveryDirect && c.NextOp > k {
				t.Fatalf("case %d: next op %d skips unrun op %d", i, c.NextOp, k)
			}
			if k < len(ap.Ops) {
				if visible(ap.Ops[k]) {
					done++
				}
				s.run(t, roleID, ap, k, k+1, docs)
			}
		}
		if c := classify(t, s, ap); c.Class != ClassAfter {
			t.Fatalf("case %d: apply not after: %+v", i, c)
		}
		if c := classify(t, s, u); c.Class != ClassBefore && !(len(u.Ops) == 0 && c.Class == ClassAfter) {
			t.Fatalf("case %d: undo not before: %+v", i, c)
		}
		s.run(t, roleID, u, 0, len(u.Ops), docs)
		if c := classify(t, s, u); c.Class != ClassAfter {
			t.Fatalf("case %d: undo not after: %+v", i, c)
		}
		zs, _ := ArtifactState(s.read(roleID))
		if !reflect.DeepEqual(xs, zs) || s.snapshot() != x {
			t.Fatalf("case %d (%d): undo(apply(x)) != x\n%s\n---\n%s", i, st, x, s.snapshot())
		}
	}
}

// plan_hash changes iff a plan_hash field changes; material_hash ignores
// the evidence identifiers but follows every other field, the impact hash
// and the gaps (§2.8).
func TestProperty_PlanAndMaterialHashFields(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	p := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2")).Apply
	base := p.HashInput()
	ph, _ := PlanHash(base)
	mh, _ := MaterialHash(MaterialHashInput{Plan: base, ImpactHash: p.ImpactHash, Gaps: p.GapRefs})
	if ph != p.PlanHash || mh != p.MaterialHash {
		t.Fatal("stored hashes are not recomputable from the plan's fields")
	}
	alt := "arn:aws:iam::" + acct + ":policy/authsec/Other"
	muts := map[string]func(*PlanHashInput){
		"control_id":         func(x *PlanHashInput) { x.ControlID = "other" },
		"kind":               func(x *PlanHashInput) { x.Kind = PlanUndo },
		"delivery":           func(x *PlanHashInput) { x.Delivery = DeliveryExport },
		"desired_attachment": func(x *PlanHashInput) { x.DesiredAttachment = AttachmentAbsent },
		"desired_arn":        func(x *PlanHashInput) { x.DesiredBoundaryARN = &alt },
		"desired_doc":        func(x *PlanHashInput) { x.DesiredDocumentHash = strPtr("sha256:00") },
		"replaced":           func(x *PlanHashInput) { x.ReplacedBoundaryARN = &alt },
		"disposition":        func(x *PlanHashInput) { x.ArtifactDisposition = DispositionDelete },
		"first_attachment":   func(x *PlanHashInput) { x.FirstAttachment = false },
		"unanalysed":         func(x *PlanHashInput) { x.Unanalysed = append(x.Unanalysed, UnanalysedItem{Key: "new"}) },
		"precondition":       func(x *PlanHashInput) { x.PreconditionHash = "sha256:11" },
		"ops":                func(x *PlanHashInput) { x.Ops = []Op{p.Ops[1], p.Ops[0]} },
		"bundle":             func(x *PlanHashInput) { x.BundleHash = "sha256:22" },
		"evidence_rev":       func(x *PlanHashInput) { x.EvidenceRev = 813 },
		"scan_run":           func(x *PlanHashInput) { x.ResourcePolicyScanRunID = strPtr("x") },
	}
	evidenceOnly := map[string]bool{"bundle": true, "evidence_rev": true, "scan_run": true}
	for name, m := range muts {
		x := base
		x.Unanalysed = append([]UnanalysedItem{}, base.Unanalysed...)
		m(&x)
		h, err := PlanHash(x)
		if err != nil {
			t.Fatal(name, err)
		}
		if h == ph {
			t.Errorf("%s: plan_hash unchanged", name)
		}
		m2, _ := MaterialHash(MaterialHashInput{Plan: x, ImpactHash: p.ImpactHash, Gaps: p.GapRefs})
		if evidenceOnly[name] != (m2 == mh) {
			t.Errorf("%s: material_hash changed=%v", name, m2 != mh)
		}
	}
	// Fields outside plan_hash (diff, refusals, documents) do not move it.
	q := p
	q.Diff.Notes = []string{"anything"}
	q.Documents = nil
	if x, _ := PlanHash(q.HashInput()); x != ph {
		t.Fatal("diff/documents must not enter plan_hash")
	}
	if m, _ := MaterialHash(MaterialHashInput{Plan: base, ImpactHash: "sha256:other", Gaps: p.GapRefs}); m == mh {
		t.Fatal("impact is material")
	}
	if m, _ := MaterialHash(MaterialHashInput{Plan: base, ImpactHash: p.ImpactHash, Gaps: []GapRef{{Key: "g", Hash: "h"}}}); m == mh {
		t.Fatal("gaps are material")
	}
}

// An unchanged rescan (a new bundle whose only differences are evidence
// identifiers and the activity facts of KEPT services) reproduces the
// material hash while the plan hash names the new evidence (§2.8, A59).
func TestProperty_MaterialHashStableAcrossEvidenceOnlyChanges(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 50; i++ {
		s := newSim()
		s.addRole(baseRole())
		remove := pick(r, 1+r.Intn(2), []string{"ec2", "sqs", "sns"})
		in := targetIn(t, s, DeliveryDirect, remove...)
		a := mustCompile(t, in)
		in.Evidence = evidenceFor(t, remove, evOpts{s3Attempt: daysAgo(float64(2 + r.Intn(20)))})
		in.Evidence.Bundle.Facts.Sources[0].Rev = 812
		in.Live.ReadAt = readAt.Add(time.Duration(r.Intn(1000)) * time.Minute)
		b := mustCompile(t, in)
		if a.Apply.PlanHash == b.Apply.PlanHash || a.Apply.MaterialHash != b.Apply.MaterialHash ||
			a.Undo.PlanHash == b.Undo.PlanHash || a.Undo.MaterialHash != b.Undo.MaterialHash {
			t.Fatalf("case %d: plan %v/%v material %v/%v", i, a.Apply.PlanHash == b.Apply.PlanHash, a.Undo.PlanHash == b.Undo.PlanHash,
				a.Apply.MaterialHash == b.Apply.MaterialHash, a.Undo.MaterialHash == b.Undo.MaterialHash)
		}
		// A new consumer is material (A23, A59).
		in.Evidence = evidenceFor(t, remove, evOpts{consumers: []ImpactConsumer{{WorkloadID: wl1, Relationship: RelExecutesAs},
			{WorkloadID: identityID, Relationship: RelExecutesAs}}})
		c := mustCompile(t, in)
		if c.Apply.MaterialHash == a.Apply.MaterialHash || c.Apply.ImpactHash == a.Apply.ImpactHash {
			t.Fatalf("case %d: a new consumer must be material", i)
		}
	}
}

// Every compiled plan, eligible or not, satisfies the 050 CHECK mirror, and
// the mirror itself refuses what 050 refuses.
func TestCheckStorable_Mirror(t *testing.T) {
	s := newSim()
	s.addRole(baseRole())
	tp := mustCompile(t, targetIn(t, s, DeliveryDirect, "ec2"))
	bad := map[string]func(*Plan){
		"iga_gov_plan_kind_chk": func(p *Plan) {
			p.DesiredAttachment = AttachmentAbsent
			p.ArtifactDisposition = DispositionDelete
			p.ReplacedBoundaryARN = strPtr("x")
			p.DesiredBoundaryARN, p.DesiredDocumentHash = nil, nil
		},
		"iga_gov_plan_attachment_chk":       func(p *Plan) { p.DesiredDocumentHash = nil },
		"iga_gov_plan_disposition_chk":      func(p *Plan) { p.ArtifactDisposition = DispositionRetainShared },
		"iga_gov_plan_first_attachment_chk": func(p *Plan) { p.ResourcePolicyScanRunID = nil },
		"iga_gov_plan_ineligible_chk":       func(p *Plan) { p.IneligibleReason = "x" },
	}
	for want, m := range bad {
		p := tp.Apply
		m(&p)
		if err := p.CheckStorable(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
	u := *tp.Undo
	u.ReplacedBoundaryARN = nil
	if err := u.CheckStorable(); err == nil || !strings.Contains(err.Error(), "iga_gov_plan_disposition_chk") {
		t.Errorf("DB106 mirror: %v", err)
	}
	u = *tp.Undo
	u.DesiredAttachment, u.DesiredBoundaryARN, u.DesiredDocumentHash = AttachmentPresent, u.ReplacedBoundaryARN, strPtr("sha256:x")
	if err := u.CheckStorable(); err == nil || !strings.Contains(err.Error(), "iga_gov_plan_disposition_chk") {
		t.Errorf("DB107 mirror: %v", err)
	}
}
