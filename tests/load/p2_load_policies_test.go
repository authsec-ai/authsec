package load

// Fixture policies, statements (with revisions and Sid-less replacements),
// resource references and targets, assignments and grants (§2.6, §4.7),
// written as projectPolicies / projectStatements / projectTargets /
// projectAssignments / projectGrants would have left them.

import (
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// loadServiceActions are the actions a statement grants on each service.
var loadServiceActions = map[string][]string{
	"s3":             {"s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetObjectVersion", "s3:GetBucketLocation"},
	"dynamodb":       {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem", "dynamodb:Scan"},
	"sqs":            {"sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"},
	"sns":            {"sns:Publish", "sns:Subscribe"},
	"kms":            {"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"},
	"secretsmanager": {"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"},
	"lambda":         {"lambda:InvokeFunction", "lambda:GetFunction"},
	"logs":           {"logs:CreateLogStream", "logs:PutLogEvents", "logs:CreateLogGroup"},
	"*":              {"s3:ListAllMyBuckets", "ec2:DescribeInstances", "cloudwatch:PutMetricData", "xray:PutTraceSegments", "sts:GetCallerIdentity", "iam:ListRoles"},
}

// loadAWSManagedNames seeds the AWS-managed policy names.
var loadAWSManagedNames = []string{"AWSLambdaBasicExecutionRole", "AmazonS3ReadOnlyAccess", "AmazonDynamoDBReadOnlyAccess",
	"CloudWatchLogsFullAccess", "AmazonSQSFullAccess", "AmazonECSTaskExecutionRolePolicy", "ReadOnlyAccess",
	"PowerUserAccess", "AWSXRayDaemonWriteAccess", "AmazonSSMManagedInstanceCore", "SecretsManagerReadWrite",
	"AmazonBedrockFullAccess", "AWSLambdaVPCAccessExecutionRole", "AmazonEC2ReadOnlyAccess", "AmazonSNSFullAccess"}

// loadResource is one resource reference (a distinct Resource text).
type loadResource struct {
	id      uuid.UUID
	text    string
	service string
	owner   *loadAcct         // the account whose statement named it first
	first   int               // the cycle it was first named
	accts   map[*loadAcct]int // naming account -> first cycle
	named   int               // positive target rows naming it
	exact   bool
	used    bool
}

// loadStmtSpec is one statement as the generator writes it into a document.
type loadStmtSpec struct {
	Sid         string
	Effect      string
	Action      []string
	NotAction   []string
	Resource    []string
	NotResource []string
	Condition   map[string]any
}

func (s loadStmtSpec) doc() map[string]any {
	out := map[string]any{"Effect": s.Effect}
	if s.Sid != "" {
		out["Sid"] = s.Sid
	}
	if len(s.Action) > 0 {
		out["Action"] = s.Action
	}
	if len(s.NotAction) > 0 {
		out["NotAction"] = s.NotAction
	}
	if len(s.Resource) > 0 {
		out["Resource"] = s.Resource
	}
	if len(s.NotResource) > 0 {
		out["NotResource"] = s.NotResource
	}
	if s.Condition != nil {
		out["Condition"] = s.Condition
	}
	return out
}

func (s loadStmtSpec) clone() loadStmtSpec {
	c := s
	c.Action = append([]string(nil), s.Action...)
	c.NotAction = append([]string(nil), s.NotAction...)
	c.Resource = append([]string(nil), s.Resource...)
	c.NotResource = append([]string(nil), s.NotResource...)
	return c
}

// loadPolVersion is one version of a policy document, from a cycle on.
type loadPolVersion struct {
	cycle     int
	versionID string
	specs     []loadStmtSpec
	doc       string
	hash      string
}

// loadPolicy is one managed or inline policy.
type loadPolicy struct {
	id       uuid.UUID
	kind     string // iga_policy.policy_kind
	name     string
	arn      string // the managed policy's ARN ("" inline)
	native   string // cloud_policy.native_id and the observations' subject
	policyID string // ANPA... ("" inline)
	holder   *loadIdent
	owner    *loadAcct          // whose passes date the policy and its statements
	accts    map[*loadAcct]bool // accounts collecting it
	cloudIDs map[*loadAcct]uuid.UUID
	obs      map[*loadAcct][]loadObs // per version, per collecting account
	versions []loadPolVersion
	stmts    []*loadStmt
	life     loadLife
}

// incarnation is PolicyIncarnationKey: every statement, assignment and grant
// key is built from it.
func (p *loadPolicy) incarnation() string {
	if p.kind == models.PolicyKindInline {
		return igagraph.Key("aws", "inline", p.holder.endpoint(), p.name)
	}
	return igagraph.Key("aws", "policy", p.policyID)
}

func (p *loadPolicy) immutable() string {
	if p.kind == models.PolicyKindInline {
		return p.holder.uid
	}
	return p.policyID
}

func (p *loadPolicy) sourceKey() string {
	if p.kind == models.PolicyKindInline {
		return igagraph.Key("aws", "inline", p.holder.arn, p.name)
	}
	return igagraph.Key("aws", p.arn)
}

// versionAt is the version in force at a cycle.
func (p *loadPolicy) versionAt(cycle int) *loadPolVersion {
	v := &p.versions[0]
	for i := range p.versions {
		if p.versions[i].cycle <= cycle {
			v = &p.versions[i]
		}
	}
	return v
}

// loadStmt is one statement row (iga_entitlements): Sid-keyed statements keep
// their key and gain revisions; a Sid-less statement edited is a new key.
type loadStmt struct {
	id      uuid.UUID
	pol     *loadPolicy
	key     string
	sid     string
	first   int
	retired int
	cur     awsdiscovery.PolicyStatement // the latest content it had
	revs    []loadRev
}

// loadRev is one iga_statement_revision.
type loadRev struct {
	from, to  int
	st        awsdiscovery.PolicyStatement
	versionID string
}

func (s *loadStmt) live() bool { return s.retired == 0 }

/* ------------------------------- resource pool ------------------------------ */

// pool generates the resource references the statements will name: per
// account in proportion, plus the workspace-wide selectors and references in
// accounts the workspace does not connect (external).
func (g *loadGen) pool() map[*loadAcct][]string {
	out := map[*loadAcct][]string{}
	per := g.share(g.shape.Resources - 4)
	for _, a := range g.accts {
		n := per[a.k]
		ext := n / 50 // 2% name an account the workspace does not connect
		for i := 0; i < n; i++ {
			team, comp := loadPick(g, loadTeams), loadPick(g, loadComponents)
			region := loadPick(g, a.regions)
			acct := a.id
			if i < ext {
				acct = loadPick(g, g.external)
			}
			var text string
			switch r := g.rng.Float64(); {
			case i < ext:
				text = fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", region, acct, g.uuid())
			case r < 0.22:
				text = fmt.Sprintf("arn:aws:s3:::%s-%s-%s-%d", a.label, team, comp, i)
			case r < 0.40:
				text = fmt.Sprintf("arn:aws:s3:::%s-%s-data-%d/*", a.label, team, i)
			case r < 0.55:
				text = fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s-%s-%d", region, acct, team, comp, i)
			case r < 0.65:
				text = fmt.Sprintf("arn:aws:sqs:%s:%s:%s-%s-%d", region, acct, team, comp, i)
			case r < 0.70:
				text = fmt.Sprintf("arn:aws:sns:%s:%s:%s-events-%d", region, acct, team, i)
			case r < 0.78:
				text = fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", region, acct, g.uuid())
			case r < 0.86:
				text = fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:%s/%s-%d-AbCdEf", region, acct, team, comp, i)
			case r < 0.93:
				text = fmt.Sprintf("arn:aws:lambda:%s:%s:function:%s-%s-%d", region, acct, team, comp, i)
			default:
				text = fmt.Sprintf("arn:aws:logs:%s:%s:log-group:/aws/lambda/%s-%s-%d:*", region, acct, team, comp, i)
			}
			out[a] = append(out[a], text)
		}
	}
	return out
}

// loadServiceOf is an ARN's service field ("*" for anything else).
func loadServiceOf(text string) string {
	parts := strings.SplitN(text, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && !strings.ContainsAny(parts[2], "*?") {
		return parts[2]
	}
	return "*"
}

// actionsFor picks 1-3 actions for a statement naming a resource.
func (g *loadGen) actionsFor(text string) []string {
	acts := loadServiceActions[loadServiceOf(text)]
	if acts == nil {
		acts = loadServiceActions["*"]
	}
	n := 1 + g.rng.Intn(3)
	seen := map[string]bool{}
	var out []string
	for i := 0; i < n; i++ {
		a := loadPick(g, acts)
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

/* --------------------------------- policies -------------------------------- */

// policies generates every policy's first version and history. Holders of
// inline policies are drawn from the identities.
func (g *loadGen) policies(pool map[*loadAcct][]string) {
	C := g.shape.Cycles
	global := []string{"*", "arn:aws:s3:::*", "arn:aws:logs:*:*:*", "arn:aws:dynamodb:*:*:table/*"}
	// AWS-managed: one object across accounts; owner is the first account
	// (assignments below guarantee it collects every one).
	for n := 0; n < g.shape.AWSManaged; n++ {
		name := fmt.Sprintf("AWSManagedPolicy%03d", n)
		if n < len(loadAWSManagedNames) {
			name = loadAWSManagedNames[n]
		}
		p := &loadPolicy{id: g.uuid(), kind: models.PolicyKindAWSManaged, name: name,
			arn: "arn:aws:iam::aws:policy/" + name, policyID: fmt.Sprintf("ANPAAWS%014d", n),
			owner: g.accts[0], life: loadLife{first: 1}}
		p.native = p.arn
		var specs []loadStmtSpec
		for i, k := 0, 3+g.rng.Intn(8); i < k; i++ {
			res := []string{"*"}
			if g.chance(0.3) {
				res = []string{loadPick(g, global[1:])}
			}
			s := loadStmtSpec{Effect: "Allow", Action: g.actionsFor(res[0]), Resource: res}
			if g.chance(0.5) {
				s.Sid = fmt.Sprintf("Stmt%d", i)
			}
			specs = append(specs, s)
		}
		p.versions = []loadPolVersion{{cycle: 1, specs: specs}}
		g.policies = append(g.policies, p)
	}

	// Customer-managed, per account: statements name the account's own
	// references with a Zipf skew (one hot bucket, a long tail), "*" in about
	// one statement in seven, and an external reference now and then.
	per := g.share(g.shape.Customer)
	for _, a := range g.accts {
		refs := pool[a]
		for n := 0; n < per[a.k]; n++ {
			team := loadPick(g, loadTeams)
			name := fmt.Sprintf("%s-%s-access-%d", team, loadPick(g, loadComponents), n)
			p := &loadPolicy{id: g.uuid(), kind: models.PolicyKindCustomerManaged, name: name,
				arn: "arn:aws:iam::" + a.id + ":policy/" + name, policyID: fmt.Sprintf("ANPA%c%015d", 'A'+rune(a.k), n),
				owner: a, life: loadLife{first: 1}}
			p.native = p.arn
			p.versions = []loadPolVersion{{cycle: 1, specs: g.statementSpecs(refs, 3+g.rng.Intn(7))}}
			g.policies = append(g.policies, p)
		}
	}

	// Inline: on roles (60%), users (30%) and groups (10%).
	var roles, users, groups []*loadIdent
	for _, i := range g.idents {
		switch i.kind {
		case models.CloudIdentityIAMRole:
			roles = append(roles, i)
		case models.CloudIdentityIAMUser:
			users = append(users, i)
		default:
			groups = append(groups, i)
		}
	}
	taken := map[string]bool{}
	for n := 0; n < g.shape.Inline; n++ {
		var holder *loadIdent
		switch r := g.rng.Float64(); {
		case r < 0.6:
			holder = loadPick(g, roles)
		case r < 0.9:
			holder = loadPick(g, users)
		default:
			holder = loadPick(g, groups)
		}
		name := fmt.Sprintf("%s-inline-%d", strings.SplitN(holder.name, "-", 2)[0], n)
		if taken[holder.arn+name] {
			continue
		}
		taken[holder.arn+name] = true
		p := &loadPolicy{id: g.uuid(), kind: models.PolicyKindInline, name: name, holder: holder,
			native: "inline:" + holder.arn + ":" + name, owner: holder.acct, life: holder.life}
		p.versions = []loadPolVersion{{cycle: holder.life.first, specs: g.statementSpecs(pool[holder.acct], 1+g.rng.Intn(4))}}
		g.policies = append(g.policies, p)
	}

	// Every reference in the pool is named by at least one statement, so
	// the graph holds all of them: an unnamed reference is no node at all.
	named := map[string]bool{}
	for _, p := range g.policies {
		for _, s := range p.versions[0].specs {
			for _, r := range append(append([]string{}, s.Resource...), s.NotResource...) {
				named[r] = true
			}
		}
	}
	var customer []*loadPolicy
	for _, p := range g.policies {
		if p.kind == models.PolicyKindCustomerManaged {
			customer = append(customer, p)
		}
	}
	for _, a := range g.accts {
		var mine []*loadPolicy
		for _, p := range customer {
			if p.owner == a {
				mine = append(mine, p)
			}
		}
		for _, text := range pool[a] {
			if named[text] {
				continue
			}
			named[text] = true
			p := loadPick(g, mine)
			i := g.rng.Intn(len(p.versions[0].specs))
			s := &p.versions[0].specs[i]
			if len(s.Resource) == 0 || len(s.Resource) >= 4 {
				p.versions[0].specs = append(p.versions[0].specs,
					loadStmtSpec{Effect: "Allow", Action: g.actionsFor(text), Resource: []string{text}})
				continue
			}
			s.Resource = append(s.Resource, text)
		}
	}
	for _, text := range global {
		if !named[text] {
			p := customer[0]
			p.versions[0].specs = append(p.versions[0].specs, loadStmtSpec{Effect: "Allow", Action: []string{"s3:ListAllMyBuckets"}, Resource: []string{text}})
		}
	}

	// History: a quarter of the customer and inline policies change. A
	// Sid-keyed statement edited in place gains a revision; a Sid-less one
	// edited is replaced (the old statement ends, a new one begins); the
	// policy's default version moves on either way.
	for _, p := range g.policies {
		if p.kind == models.PolicyKindAWSManaged && !g.chance(0.05) {
			continue
		}
		var cycles []int
		switch r := g.rng.Float64(); {
		case r < 0.15:
			cycles = []int{2}
		case r < 0.20:
			cycles = []int{3}
		case r < 0.25:
			cycles = []int{2, 4}
		}
		for _, c := range cycles {
			if c <= p.versions[0].cycle || (p.life.retired > 0 && c >= p.life.retired) || c > C {
				continue
			}
			prev := p.versions[len(p.versions)-1].specs
			next := make([]loadStmtSpec, len(prev))
			for i := range prev {
				next[i] = prev[i].clone()
			}
			for edits := 1 + g.rng.Intn(2); edits > 0; edits-- {
				s := &next[g.rng.Intn(len(next))]
				if len(s.Action) == 0 {
					continue
				}
				// A new action, never a new resource: targets stay the
				// references the statement names now (D-27f).
				extra := g.actionsFor(firstOr(s.Resource, "*"))[0]
				if !contains(s.Action, extra) {
					s.Action = append(s.Action, extra)
				} else {
					s.Action = s.Action[:len(s.Action)-1]
					if len(s.Action) == 0 {
						s.Action = []string{extra}
					}
				}
			}
			p.versions = append(p.versions, loadPolVersion{cycle: c, specs: next})
		}
	}

	for _, p := range g.policies {
		for i := range p.versions {
			v := &p.versions[i]
			v.versionID = fmt.Sprintf("v%d", i+1)
			if p.kind == models.PolicyKindInline {
				v.versionID = "" // an inline policy has no versions
			}
			docs := make([]map[string]any, len(v.specs))
			for j, s := range v.specs {
				docs[j] = s.doc()
			}
			v.doc = string(loadMarshal(map[string]any{"Version": "2012-10-17", "Statement": docs}))
			v.hash = loadHash(v.doc)
		}
		g.statements(p)
	}
}

// statementSpecs draws n statements naming references from refs.
func (g *loadGen) statementSpecs(refs []string, n int) []loadStmtSpec {
	var out []loadStmtSpec
	for i := 0; i < n; i++ {
		s := loadStmtSpec{Effect: "Allow"}
		if g.chance(0.7) {
			s.Sid = fmt.Sprintf("S%d%s", i, loadPick(g, []string{"Read", "Write", "Use", "Manage", "Invoke"}))
		}
		k := 1
		if g.chance(0.35) {
			k = 2
		}
		seen := map[string]bool{}
		for j := 0; j < k; j++ {
			var text string
			switch r := g.rng.Float64(); {
			case r < 0.14:
				text = "*"
			default:
				text = refs[g.zipf(len(refs), 1.1)]
			}
			if !seen[text] {
				seen[text] = true
				s.Resource = append(s.Resource, text)
			}
		}
		s.Action = g.actionsFor(s.Resource[0])
		switch r := g.rng.Float64(); {
		case r < 0.15:
			s.Effect = "Deny"
		case r < 0.17:
			s.Action, s.NotAction = nil, []string{"iam:*", "organizations:*"}
			s.Resource = []string{"*"}
		case r < 0.19 && s.Resource[0] != "*":
			s.NotResource, s.Resource = s.Resource, nil
			s.Action = []string{loadServiceOf(s.NotResource[0]) + ":*"}
			if loadServiceOf(s.NotResource[0]) == "*" {
				s.Action = []string{"s3:*"}
			}
		}
		if g.chance(0.10) {
			s.Condition = map[string]any{"Bool": map[string]any{"aws:SecureTransport": "true"}}
		}
		out = append(out, s)
	}
	// Sids must be unique within a document to key statements by Sid (§2.6).
	used := map[string]bool{}
	for i := range out {
		if out[i].Sid != "" {
			if used[out[i].Sid] {
				out[i].Sid = ""
			}
			used[out[i].Sid] = true
		}
	}
	return out
}

// statements parses every version of a policy with the collector's parser
// and keys its statements as projectStatements does; content changes become
// revisions (Sid-keyed) or replacements (Sid-less).
func (g *loadGen) statements(p *loadPolicy) {
	byKey := map[string]*loadStmt{}
	for vi, v := range p.versions {
		parsed, skipped, err := awsdiscovery.ParsePolicyDocument(v.doc)
		if err != nil || skipped > 0 {
			panic(fmt.Sprintf("load: policy %s version %d: %v (%d skipped)", p.native, vi, err, skipped))
		}
		sids, seen := igagraph.CountSids(parsed), map[string]int{}
		present := map[string]bool{}
		for _, st := range parsed {
			key, hash := igagraph.StatementKey(p.incarnation(), st, sids, seen)
			present[key] = true
			s := byKey[key]
			if s == nil {
				s = &loadStmt{id: g.uuid(), pol: p, key: key, sid: st.Sid, first: v.cycle}
				byKey[key] = s
				p.stmts = append(p.stmts, s)
			}
			if igagraph.SidKeyed(key) {
				if n := len(s.revs); n == 0 || s.revs[n-1].st.ContentHash() != hash {
					if n > 0 {
						s.revs[n-1].to = v.cycle
					}
					s.revs = append(s.revs, loadRev{from: v.cycle, st: st, versionID: v.versionID})
				}
			}
			s.cur = st
		}
		for key, s := range byKey {
			if !present[key] && s.retired == 0 {
				s.retired = v.cycle
			}
		}
	}
	if p.life.retired > 0 {
		for _, s := range p.stmts {
			if s.retired == 0 || s.retired > p.life.retired {
				s.retired = p.life.retired
			}
			if n := len(s.revs); n > 0 && s.revs[n-1].to == 0 {
				s.revs[n-1].to = p.life.retired
			}
		}
	}
}

/* ------------------------------- assignments ------------------------------- */

// loadAssign is one policy assignment (attachment, inline or boundary).
type loadAssign struct {
	id     uuid.UUID
	pol    *loadPolicy
	holder *loadIdent
	kind   string
	span   loadSpan
}

// assignments decides who holds what: roles 1-4 attached policies (their
// account's customer policies or AWS-managed ones), users 0-2 and groups
// 1-4; every inline policy on its holder; a boundary on some roles and users.
// Every AWS-managed policy is attached in the first account at least once, so
// that account collects it and dates it.
func (g *loadGen) assignments() []*loadAssign {
	var managed []*loadPolicy
	customer := map[*loadAcct][]*loadPolicy{}
	var inline []*loadPolicy
	for _, p := range g.policies {
		switch p.kind {
		case models.PolicyKindAWSManaged:
			managed = append(managed, p)
		case models.PolicyKindCustomerManaged:
			customer[p.owner] = append(customer[p.owner], p)
		default:
			inline = append(inline, p)
		}
	}
	var out []*loadAssign
	seen := map[string]bool{}
	add := func(p *loadPolicy, holder *loadIdent, kind string) *loadAssign {
		k := p.id.String() + holder.id.String() + kind
		if seen[k] {
			return nil
		}
		seen[k] = true
		from := holder.life.first
		if p.life.first > from {
			from = p.life.first
		}
		span := loadSpan{from: from, to: holder.life.retired, reason: models.EndedNotSeen}
		switch r := g.rng.Float64(); {
		case r < 0.05 && from < 2 && kind != models.CloudAttachmentInline:
			span.from = 2 // attached later
		case r < 0.08 && span.to == 0 && kind != models.CloudAttachmentInline:
			span.to = 3 // detached
		}
		if span.to > 0 && span.to <= span.from {
			return nil
		}
		as := &loadAssign{id: g.uuid(), pol: p, holder: holder, kind: kind, span: span}
		out = append(out, as)
		if p.kind != models.PolicyKindInline {
			if p.accts == nil {
				p.accts = map[*loadAcct]bool{}
			}
			p.accts[holder.acct] = true
		}
		return as
	}
	var firstRoles []*loadIdent
	for _, i := range g.idents {
		if i.kind == models.CloudIdentityIAMRole && i.acct == g.accts[0] && i.life.first == 1 && i.life.live() {
			firstRoles = append(firstRoles, i)
		}
	}
	for n, p := range managed {
		add(p, firstRoles[n%len(firstRoles)], models.CloudAttachmentAttached)
	}
	for _, i := range g.idents {
		var n int
		switch i.kind {
		case models.CloudIdentityIAMRole:
			n = 1 + g.rng.Intn(4)
		case models.CloudIdentityIAMUser:
			n = g.rng.Intn(3)
		default:
			n = 1 + g.rng.Intn(4)
		}
		for ; n > 0; n-- {
			p := loadPick(g, customer[i.acct])
			if g.chance(0.35) {
				p = managed[g.zipf(len(managed), 1.2)]
			}
			add(p, i, models.CloudAttachmentAttached)
		}
		if i.kind != models.CloudIdentityIAMGroup && g.chance(0.06) {
			b := managed[7%len(managed)] // PowerUserAccess as the boundary, as in the lab
			if as := add(b, i, models.CloudAttachmentBoundary); as != nil && as.span.to == 0 {
				i.boundary = b
			}
		}
	}
	for _, p := range inline {
		add(p, p.holder, models.CloudAttachmentInline)
	}
	for _, p := range g.policies {
		if p.kind == models.PolicyKindInline {
			p.accts = map[*loadAcct]bool{p.owner: true}
		}
		if p.accts == nil {
			p.accts = map[*loadAcct]bool{p.owner: true}
		}
	}
	return out
}

/* ---------------------------------- rows ----------------------------------- */

// policyRows writes each policy's collector rows (cloud_policy and one
// observation per version per collecting account) and graph rows (policy,
// statements, revisions, targets, resources, support, events).
func (g *loadGen) policyRows() {
	C := g.shape.Cycles
	for _, p := range g.policies {
		cur := p.versions[len(p.versions)-1]
		p.cloudIDs, p.obs = map[*loadAcct]uuid.UUID{}, map[*loadAcct][]loadObs{}
		accts := loadAcctsOf(g, p.accts)
		for _, a := range accts {
			cid := g.uuid()
			p.cloudIDs[a] = cid
			var holder *uuid.UUID
			kind := "managed"
			if p.kind == models.PolicyKindInline {
				kind = "inline"
				holder = &p.holder.cloudID
			}
			var cloudRef *uuid.UUID
			if p.life.live() {
				cloudRef = &cid
				g.rows.add("cloud_policy", cid, g.ws, a.conn, kind, p.native, holder, p.name, p.policyID,
					p.kind == models.PolicyKindAWSManaged, cur.versionID, loadJSON(cur.doc), cur.hash, "", C,
					g.at(p.versions[0].cycle, a.k), a.run(C).at)
			}
			api := "iam:GetAccountAuthorizationDetails"
			if p.kind == models.PolicyKindAWSManaged {
				api = "iam:GetPolicyVersion"
			}
			last := p.life.lastCycle(C)
			for vi, v := range p.versions {
				to := last
				if vi+1 < len(p.versions) {
					to = p.versions[vi+1].cycle - 1
				}
				facts := map[string]any{"name": p.name, "version_id": v.versionID, "document_hash": v.hash,
					"document_error": "", "observed_subject": "policy:" + cid.String()}
				if p.kind == models.PolicyKindInline {
					facts["holder"] = p.holder.arn
				} else {
					facts["arn"], facts["policy_id"], facts["aws_managed"] = p.arn, p.policyID, p.kind == models.PolicyKindAWSManaged
				}
				var ref *uuid.UUID
				if vi == len(p.versions)-1 {
					ref = cloudRef // an older version's subject is SET NULL once superseded
				}
				p.obs[a] = append(p.obs[a], g.observe(a, "policy_id", ref, api, models.SurfaceIAMPolicies, p.native, facts, v.cycle, to))
			}
		}

		lifecycle, reason := p.life.lifecycle()
		nativeRef := p.arn
		first := p.versions[0].cycle
		lastAt := p.owner.run(p.life.lastCycle(C)).at
		g.rows.add("iga_policy", p.id, g.ws, "aws", p.kind, p.name, nativeRef, p.sourceKey(), models.ContinuityImmutable,
			p.immutable(), cur.versionID, cur.hash, lifecycle, reason, g.at(first, p.owner.k), lastAt)
		for _, a := range accts {
			life := p.life
			if a != p.owner {
				life.first = 1
			}
			g.support(a, "policy_id", p.id, a.nodePart(models.ObjectPolicy, "", ""), life)
		}
		g.events(p.owner, "policy_id", p.id, p.life)

		for _, s := range p.stmts {
			g.statementRows(p, s, accts)
		}
	}
}

// statementRows writes one statement: the entitlement row (its latest
// content), revisions, targets (and the references they create), support and
// events.
func (g *loadGen) statementRows(p *loadPolicy, s *loadStmt, accts []*loadAcct) {
	C := g.shape.Cycles
	st := s.cur
	life := loadLife{first: s.first, retired: s.retired}
	lifecycle, reason := life.lifecycle()
	idx := st.Index
	normalized := models.NormalizedRights{Verbs: st.Actions,
		Constrained: st.Condition != "" || len(st.NotActions) > 0 || len(st.NotResources) > 0}
	lastAt := p.owner.run(life.lastCycle(C)).at
	g.rows.add("iga_entitlements", s.id, g.ws, "aws_statement", loadJSON(st.Raw), loadMarshal(normalized), lifecycle, "aws",
		s.key, models.ContinuityImmutable, p.immutable(), g.at(s.first, p.owner.k), lastAt, reason, p.id, s.key, st.Sid, &idx,
		st.Effect, st.ContentHash(), len(st.NotActions) > 0 || len(st.NotResources) > 0, st.Condition != "",
		g.at(s.first, p.owner.k), lastAt)
	for _, r := range s.revs {
		var to *loadRun
		if r.to > 0 {
			to = p.owner.run(r.to)
		}
		var validTo any
		if to != nil {
			validTo = to.at
		}
		g.rows.add("iga_statement_revision", g.uuid(), g.ws, s.id, r.st.ContentHash(), loadJSON(r.st.Raw), r.versionID,
			p.owner.run(r.from).at, validTo, p.owner.run(r.from).id)
	}
	// Targets: what the statement's content names (projectTargets). A
	// NotResource-only statement is scoped by the implicit "*" selector.
	type tgt struct {
		text, mode string
		ord        int
	}
	var targets []tgt
	for i, r := range st.Resources {
		targets = append(targets, tgt{r, models.TargetResource, i})
	}
	for i, r := range st.NotResources {
		targets = append(targets, tgt{r, models.TargetNotResource, i})
	}
	if len(st.NotResources) > 0 && len(st.Resources) == 0 {
		targets = append(targets, tgt{"*", models.TargetResource, 0})
	}
	dedupe := map[string]bool{}
	for _, t := range targets {
		if dedupe[t.text+t.mode] {
			continue
		}
		dedupe[t.text+t.mode] = true
		res := g.resourceRef(t.text, accts, s.first)
		if t.mode == models.TargetResource && st.Effect == models.EffectAllow && s.live() {
			res.named++
		}
		g.rows.add("iga_entitlement_target", g.uuid(), g.ws, s.id, res.id, t.mode, t.ord)
	}
	for _, a := range accts {
		g.support(a, "entitlement_id", s.id, a.nodePart(models.ObjectEntitlement, "", ""), life)
	}
	g.events(p.owner, "entitlement_id", s.id, life)
}

// resourceRef returns (creating once) the reference for a text, recording
// which accounts name it and from when.
func (g *loadGen) resourceRef(text string, accts []*loadAcct, cycle int) *loadResource {
	r := g.resources[text]
	if r == nil {
		r = &loadResource{id: g.uuid(), text: text, service: loadServiceOf(text), owner: accts[0], first: cycle,
			accts: map[*loadAcct]int{}}
		g.resources[text] = r
		g.resList = append(g.resList, r)
	}
	for _, a := range accts {
		if c, ok := r.accts[a]; !ok || cycle < c {
			r.accts[a] = cycle
		}
		if cycle < r.first || (cycle == r.first && a.k < r.owner.k) {
			r.first, r.owner = cycle, a
		}
	}
	return r
}

// resourceRows writes every reference: the graph row with the attributes its
// text states (describeResource), one support row per naming account, its
// first_seen event, and a resource-policy observation for exact buckets and
// keys of connected accounts.
func (g *loadGen) resourceRows() {
	connected := map[string]bool{}
	for _, a := range g.accts {
		connected[a.id] = true
	}
	C := g.shape.Cycles
	for _, r := range g.resList {
		kind, attrs := loadDescribeResource(r.text, connected)
		r.exact = attrs["reference"] == "exact"
		lastAt := g.pubs[len(g.pubs)-1].at
		g.rows.add("iga_resources", r.id, g.ws, r.owner.scope, kind, r.text, "unknown", models.IGALifecycleActive, "aws",
			igagraph.ResourceRefKey(r.text), models.ContinuityRecognitionOnly, "", g.at(r.first, r.owner.k), lastAt, "",
			loadMarshal(attrs), g.at(r.first, r.owner.k), lastAt)
		for _, a := range loadAcctsOfInt(g, r.accts) {
			g.support(a, "resource_id", r.id, a.nodePart(models.ObjectResource, "", ""), loadLife{first: r.accts[a]})
		}
		g.events(r.owner, "resource_id", r.id, loadLife{first: r.first})
		// The resource policy of an exact bucket, or of a key in a connected
		// account, was read by the naming account's resource-policy pass.
		acct, _ := attrs["account"].(string)
		if r.exact && (kind == "s3_bucket" || (kind == "kms_key" && connected[acct])) {
			api := map[string]string{"s3_bucket": "s3:GetBucketPolicy", "kms_key": "kms:GetKeyPolicy"}[kind]
			last := C
			if r.owner.k == 2 {
				last = C - 1 // resource_policies was denied in this account's last run
			}
			g.observe(r.owner, "", nil, api, models.SurfaceResourcePolicies, r.text,
				map[string]any{"kind": kind, "has_deny": g.chance(0.2), "statements": 1 + g.rng.Intn(3), "parse_failed": false},
				r.first, last)
		}
	}
}

// loadDescribeResource mirrors igagraph's describeResource (unexported): the
// kind of a reference and what its text states -- account and region only
// when the ARN carries them, never the scanning account (§1.4).
func loadDescribeResource(text string, connected map[string]bool) (string, map[string]any) {
	attrs := map[string]any{"existence": "not_verified"}
	kind := "unknown"
	switch {
	case strings.ContainsAny(text, "*?"):
		kind = "selector"
		attrs["reference"] = "selector"
	case strings.HasPrefix(text, "arn:"):
		attrs["reference"] = "exact"
		if typed := awsdiscovery.TypeResourceARN(text); typed != nil && typed.Kind != "" {
			kind = typed.Kind
		}
	default:
		attrs["reference"] = "exact"
	}
	if parts := strings.SplitN(text, ":", 6); len(parts) == 6 && parts[0] == "arn" {
		if parts[3] != "" && !strings.ContainsAny(parts[3], "*?") {
			attrs["region"] = parts[3]
		}
		if acct := parts[4]; acct != "" && !strings.ContainsAny(acct, "*?") {
			attrs["account"] = acct
			attrs["account_connected"] = connected[acct]
		}
	}
	return kind, attrs
}

// assignmentRows writes each assignment, its grants (one per Allow statement
// valid while it is, projectGrants), and both junctions (the policy
// version's observation and the holder's, attachEvidence).
func (g *loadGen) assignmentRows(assigns []*loadAssign) {
	C := g.shape.Cycles
	for _, as := range assigns {
		a := as.holder.acct
		p := as.pol
		state, reason := as.span.state()
		last := a.run(as.span.lastCycle(C))
		key := igagraph.AssignmentKey(p.incarnation(), as.holder.endpoint(), as.kind)
		g.rows.add("iga_policy_assignment", as.id, g.ws, p.id, as.holder.id, as.kind, models.BasisDeclared, state,
			g.at(as.span.from, a.k), g.validTo(a, as.span), last.at, last.id, reason, key,
			a.edgePart("assignment", "", ""), a.conn)
		polObs := p.obs[a]
		g.link("iga_assignment_evidence", as.id, as.span, append([]loadObs{as.holder.obs}, polObs...)...)
		if as.span.to == 0 && len(g.h.assignments) < 60 {
			g.h.assignments = append(g.h.assignments, as.id)
		}
		if as.kind == models.CloudAttachmentBoundary {
			continue // a boundary limits; it never grants
		}
		for _, s := range p.stmts {
			if s.cur.Effect != models.EffectAllow {
				continue
			}
			span := as.span
			if s.first > span.from {
				span.from = s.first
			}
			if s.retired > 0 && (span.to == 0 || s.retired < span.to) {
				span.to, span.reason = s.retired, models.EndedNotSeen
			}
			if span.to > 0 && span.to <= span.from {
				continue
			}
			gstate, greason := span.state()
			glast := a.run(span.lastCycle(C))
			id := g.uuid()
			g.rows.add("iga_access_edges", id, g.ws, "identity_account", as.holder.id, s.id, "outbound", "aws_policy",
				models.CalcPartial, models.ConclusionUnknown, as.holder.id, "aws", models.BasisDeclared, gstate,
				g.at(span.from, a.k), g.validTo(a, span), glast.at, glast.id, greason,
				igagraph.GrantKey(key, s.key), a.edgePart("access_edge", "", ""), a.conn, as.id,
				g.at(span.from, a.k), glast.at)
			g.link("iga_access_edge_evidence", id, span, append([]loadObs{as.holder.obs}, polObs...)...)
			if span.to == 0 {
				g.grantsByHolder[as.holder] = append(g.grantsByHolder[as.holder], id)
				if len(g.h.grants) < 60 && g.chance(0.01) {
					g.h.grants = append(g.h.grants, id)
				}
			}
		}
	}
	// A grouped edge (D-79): the most grants one holder has, up to the 50
	// claims one /evidence request takes.
	for _, i := range g.idents {
		if gs := g.grantsByHolder[i]; len(gs) > len(g.h.groupedGrants) {
			if len(gs) > 50 {
				gs = gs[:50]
			}
			g.h.groupedGrants = gs
		}
	}
}

// memberships writes user --member_of--> group for each user's 1-3 groups
// (projectMemberships), some joining late and some leaving.
func (g *loadGen) memberships() {
	C := g.shape.Cycles
	for _, a := range g.accts {
		var groups []*loadIdent
		for _, i := range g.idents {
			if i.acct == a && i.kind == models.CloudIdentityIAMGroup {
				groups = append(groups, i)
			}
		}
		part := a.edgePart(models.RelTypeMemberOf, "", "")
		for _, u := range g.idents {
			if u.acct != a || u.kind != models.CloudIdentityIAMUser {
				continue
			}
			seen := map[*loadIdent]bool{}
			for n := 1 + g.rng.Intn(3); n > 0; n-- {
				grp := groups[g.zipf(len(groups), 0.8)]
				if seen[grp] {
					continue
				}
				seen[grp] = true
				span := loadSpan{from: u.life.first, to: u.life.retired, reason: models.EndedNotSeen}
				switch r := g.rng.Float64(); {
				case r < 0.03 && span.from == 1:
					span.from = 2
				case r < 0.06 && span.to == 0:
					span.to = 3
				}
				state, reason := span.state()
				last := a.run(span.lastCycle(C))
				id := g.uuid()
				g.rows.add("iga_relationship", id, g.ws, models.RelTypeMemberOf, u.id, nil, nil, grp.id,
					models.BasisDeclared, state, g.at(span.from, a.k), g.validTo(a, span), last.at, last.id, reason,
					igagraph.RelationshipKey(models.RelTypeMemberOf, u.endpoint(), grp.endpoint()), part, a.conn,
					"", nil, "", g.at(span.from, a.k), last.at)
				g.link("iga_relationship_evidence", id, span, u.obs)
				if span.to == 0 {
					grp.users++
				}
			}
		}
	}
}

// loadAcctsOf returns a set's accounts in account order.
func loadAcctsOf(g *loadGen, set map[*loadAcct]bool) []*loadAcct {
	var out []*loadAcct
	for _, a := range g.accts {
		if set[a] {
			out = append(out, a)
		}
	}
	return out
}

func loadAcctsOfInt(g *loadGen, set map[*loadAcct]int) []*loadAcct {
	var out []*loadAcct
	for _, a := range g.accts {
		if _, ok := set[a]; ok {
			out = append(out, a)
		}
	}
	return out
}

func firstOr(xs []string, def string) string {
	if len(xs) == 0 {
		return def
	}
	return xs[0]
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
