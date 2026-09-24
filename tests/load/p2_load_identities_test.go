package load

// Fixture identities (roles, users, groups), their trust documents and the
// can_assume edges and external principals the projector derives from them
// (§4.7, D-41, D-42, D-44), plus users' access keys.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

var (
	loadTeams = []string{"payments", "billing", "search", "orders", "identity", "ledger", "catalog",
		"shipping", "fraud", "notify", "reports", "ingest", "ml", "support", "auth", "inventory",
		"pricing", "profile", "analytics", "gateway", "checkout", "risk", "media", "email", "sync",
		"export", "audit", "docs", "chat", "feed"}
	loadComponents = []string{"api", "worker", "consumer", "processor", "scheduler", "handler", "etl",
		"indexer", "router", "webhook", "cron", "stream", "batch", "agent", "bridge"}
	loadFirst = []string{"alex", "priya", "sam", "jordan", "li", "maria", "noah", "fatima", "omar",
		"yuki", "chen", "ana", "ravi", "sara", "tom", "ines", "kofi", "lena", "raj", "zoe"}
	loadLast = []string{"smith", "patel", "garcia", "kim", "nguyen", "silva", "khan", "muller",
		"rossi", "tanaka", "okafor", "haddad", "novak", "berg", "costa", "iyer"}
)

// loadIdent is one IAM role, user or group.
type loadIdent struct {
	id      uuid.UUID
	cloudID uuid.UUID // cloud_identity row; uuid.Nil once the identity is gone
	acct    *loadAcct
	kind    string
	name    string
	arn     string
	uid     string
	path    string
	life    loadLife
	// service is the trusted service principal of an execution role
	// ("lambda.amazonaws.com" ...); "" for a role people or other roles assume.
	service string
	tags    map[string]string
	// boundary is the permissions boundary policy, when one is set.
	boundary *loadPolicy
	trustDoc json.RawMessage
	attrs    map[string]any // provider_attrs trust flags
	obs      loadObs
	// users is the live workloads using it (hub selection): through executes_as,
	// or, for an ecsTaskExecutionRole, through task_execution_role.
	users int
}

func (i *loadIdent) sourceKey() string { return igagraph.IdentityARNKey(i.arn) }

// endpoint is the identity inside an edge key: its immutable key (EndpointKey).
func (i *loadIdent) endpoint() string { return igagraph.Key("aws", "uid", i.uid) }

// loadExternal is one iga_external_principal (D-42).
type loadExternal struct {
	id                         uuid.UUID
	issuer, subject, mechanism string
	key                        string
	first                      *loadRun
	edges                      int
}

// identities generates every account's roles, users and groups. Trust
// documents are generated after, because they name each other.
func (g *loadGen) identities() {
	roles, users, groups := g.share(g.shape.Roles), g.share(g.shape.Users), g.share(g.shape.Groups)
	for _, a := range g.accts {
		seq := 0
		uid := func(prefix string) string {
			seq++
			return fmt.Sprintf("%s%c%016d", prefix, 'A'+rune(a.k), seq)
		}
		mk := func(kind, name, path, prefix string) *loadIdent {
			resource := map[string]string{models.CloudIdentityIAMRole: "role", models.CloudIdentityIAMUser: "user",
				models.CloudIdentityIAMGroup: "group"}[kind]
			arn := "arn:aws:iam::" + a.id + ":" + resource + path + name
			i := &loadIdent{id: g.uuid(), cloudID: g.uuid(), acct: a, kind: kind, name: name, arn: arn,
				uid: uid(prefix), path: path, life: loadLife{first: 1}}
			if g.chance(0.4) {
				i.tags = map[string]string{"team": loadPick(g, loadTeams), "env": a.label}
			}
			g.idents = append(g.idents, i)
			g.identByARN[arn] = i
			return i
		}
		// The ECS task execution role every task definition in the account
		// names (task_execution_role): the heaviest Used-by of all.
		ecs := mk(models.CloudIdentityIAMRole, "ecsTaskExecutionRole", "/", "AROA")
		ecs.service = "ecs-tasks.amazonaws.com"
		for n := 1; n < roles[a.k]; n++ {
			team, comp := loadPick(g, loadTeams), loadPick(g, loadComponents)
			var i *loadIdent
			switch r := g.rng.Float64(); {
			case r < 0.36:
				i = mk(models.CloudIdentityIAMRole, fmt.Sprintf("lambda-%s-%s-exec-%d", team, comp, n), "/service-role/", "AROA")
				i.service = "lambda.amazonaws.com"
			case r < 0.48:
				i = mk(models.CloudIdentityIAMRole, fmt.Sprintf("ecs-%s-%s-task-%d", team, comp, n), "/", "AROA")
				i.service = "ecs-tasks.amazonaws.com"
			case r < 0.57:
				i = mk(models.CloudIdentityIAMRole, fmt.Sprintf("ec2-%s-%s-%d", team, comp, n), "/", "AROA")
				i.service = "ec2.amazonaws.com"
			case r < 0.60:
				i = mk(models.CloudIdentityIAMRole, fmt.Sprintf("AmazonBedrockExecutionRoleForAgents_%s%d", team, n), "/service-role/", "AROA")
				i.service = "bedrock.amazonaws.com"
			default:
				i = mk(models.CloudIdentityIAMRole, fmt.Sprintf("%s-%s-%d", team,
					loadPick(g, []string{"admin", "deploy", "readonly", "operator", "ci", "breakglass", "auditor"}), n), "/", "AROA")
				if g.chance(0.02) {
					i.life.retired = 3
				}
			}
			if i.life.retired == 0 && g.chance(0.03) {
				i.life.first = 2
			}
		}
		for n := 0; n < users[a.k]; n++ {
			i := mk(models.CloudIdentityIAMUser, fmt.Sprintf("%s.%s%d", loadPick(g, loadFirst), loadPick(g, loadLast), n), "/", "AIDA")
			switch {
			case g.chance(0.03):
				i.life.retired = 3
			case g.chance(0.04):
				i.life.first = 2
			}
		}
		for n := 0; n < groups[a.k]; n++ {
			mk(models.CloudIdentityIAMGroup, fmt.Sprintf("team-%s-%d", loadTeams[n%len(loadTeams)], n), "/", "AGPA")
		}
	}
}

// liveIdents returns an account's live identities of a kind.
func (g *loadGen) liveIdents(a *loadAcct, kind string, exec bool) []*loadIdent {
	var out []*loadIdent
	for _, i := range g.idents {
		if i.acct == a && i.kind == kind && i.life.live() && (i.service != "") == exec {
			out = append(out, i)
		}
	}
	return out
}

/* ---------------------------------- trust ---------------------------------- */

// trust gives every role a trust document and derives its can_assume edges:
// execution roles trust their service; the rest trust other roles and users
// (in their own and other connected accounts, including mutual trust, so
// the graph has cycles), external accounts with an ExternalId condition,
// GitHub's OIDC provider, a SAML provider, or their own account; a few carry
// a Deny statement.
func (g *loadGen) trust() {
	var people []*loadIdent // roles and users other roles may trust
	for _, i := range g.idents {
		if i.kind != models.CloudIdentityIAMGroup && i.service == "" {
			people = append(people, i)
		}
	}
	mutual := map[*loadIdent][]string{}
	for _, role := range g.idents {
		if role.kind != models.CloudIdentityIAMRole {
			continue
		}
		var stmts []map[string]any
		switch {
		case role.service != "":
			stmts = append(stmts, map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole",
				"Principal": map[string]any{"Service": role.service}})
		default:
			switch r := g.rng.Float64(); {
			case r < 0.55:
				var arns []string
				for n := 1 + g.rng.Intn(3); n > 0; n-- {
					p := loadPick(g, people)
					if p != role {
						arns = append(arns, p.arn)
					}
				}
				// Mutual trust: the named role trusts this one back, so
				// can_assume has cycles (A -> B -> A) the traverser must cope with.
				if len(arns) > 0 && g.chance(0.15) {
					if back := g.identByARN[arns[0]]; back.kind == models.CloudIdentityIAMRole {
						mutual[back] = append(mutual[back], role.arn)
					}
				}
				if len(arns) > 0 {
					stmts = append(stmts, map[string]any{"Sid": "AllowAssumeFromPeers", "Effect": "Allow",
						"Action": "sts:AssumeRole", "Principal": map[string]any{"AWS": arns}})
				}
			case r < 0.70:
				stmts = append(stmts, map[string]any{"Sid": "VendorAccess", "Effect": "Allow", "Action": "sts:AssumeRole",
					"Principal": map[string]any{"AWS": "arn:aws:iam::" + loadPick(g, g.external) + ":root"},
					"Condition": map[string]any{"StringEquals": map[string]any{"sts:ExternalId": "vendor-" + role.uid[4:12]}}})
			case r < 0.76:
				stmts = append(stmts, map[string]any{"Sid": "GitHubDeploy", "Effect": "Allow",
					"Action":    "sts:AssumeRoleWithWebIdentity",
					"Principal": map[string]any{"Federated": "arn:aws:iam::" + role.acct.id + ":oidc-provider/token.actions.githubusercontent.com"},
					"Condition": map[string]any{"StringLike": map[string]any{
						"token.actions.githubusercontent.com:sub": "repo:acme/" + loadPick(g, loadTeams) + ":ref:refs/heads/main"}}})
			case r < 0.79:
				stmts = append(stmts, map[string]any{"Effect": "Allow", "Action": "sts:AssumeRoleWithSAML",
					"Principal": map[string]any{"Federated": "arn:aws:iam::" + role.acct.id + ":saml-provider/Okta"}})
			default:
				stmts = append(stmts, map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole",
					"Principal": map[string]any{"AWS": "arn:aws:iam::" + role.acct.id + ":root"}})
			}
			if g.chance(0.03) {
				stmts = append(stmts, map[string]any{"Sid": "NoExternalSessions", "Effect": "Deny", "Action": "sts:AssumeRole",
					"Principal": map[string]any{"AWS": "*"},
					"Condition": map[string]any{"StringNotEquals": map[string]any{"aws:PrincipalOrgID": "o-acme"}}})
			}
		}
		role.trustDoc = json.RawMessage(loadMarshal(map[string]any{"Version": "2012-10-17", "Statement": stmts}))
	}
	for role, arns := range mutual {
		var doc map[string]any
		_ = json.Unmarshal(role.trustDoc, &doc)
		st, _ := doc["Statement"].([]any)
		st = append(st, map[string]any{"Sid": "MutualAssume", "Effect": "Allow", "Action": "sts:AssumeRole",
			"Principal": map[string]any{"AWS": arns}})
		doc["Statement"] = st
		role.trustDoc = json.RawMessage(loadMarshal(doc))
	}
	for _, role := range g.idents {
		if role.kind != models.CloudIdentityIAMRole {
			continue
		}
		doc, err := awsdiscovery.ParseTrustDocument(role.trustDoc)
		if err != nil || len(doc.Skipped) > 0 {
			panic(fmt.Sprintf("load: trust document of %s: %v", role.arn, err))
		}
		// What projectIdentities writes into provider_attrs (trustFlags).
		role.attrs = map[string]any{igagraph.TrustHasDenyAttr: doc.HasDeny(),
			igagraph.TrustHasNotPrincipalAttr: doc.HasNotPrincipal()}
	}
}

// trustAll writes every role's can_assume edges. After identityRows: each
// edge links the role's observation, the read of its trust document (§4.8).
func (g *loadGen) trustAll() {
	for _, role := range g.idents {
		if role.kind == models.CloudIdentityIAMRole {
			g.trustEdges(role)
		}
	}
}

// trustEdges parses a role's trust document with the collector's parser and
// writes its can_assume edges the way projectTrust does: Deny and
// NotPrincipal statements set flags, never edges (D-44); an exact ARN of a
// live identity in a connected account is that identity (D-41 rule 2); any
// other principal is an external principal (rule 3).
func (g *loadGen) trustEdges(role *loadIdent) {
	doc, _ := awsdiscovery.ParseTrustDocument(role.trustDoc) // parsed once already, in trust()
	a := role.acct
	part := a.edgePart(models.RelTypeCanAssume, igagraph.TrustPartitionKind, "")
	sids, seen := igagraph.CountTrustSids(doc.Statements), map[string]int{}
	C := g.shape.Cycles
	for _, st := range doc.Statements {
		stKey, _ := igagraph.TrustStatementKey(role.endpoint(), st, sids, seen)
		if st.Effect == models.EffectDeny || st.HasNotPrincipal() {
			continue
		}
		var cond any // NULL when the statement has no Condition (031)
		if len(st.Condition) > 0 {
			cond = loadJSON(st.Condition)
		}
		for _, sub := range st.Subjects() {
			from := role.life.first
			end := role.life.retired // the role itself ends its edges
			var src *loadIdent
			if sub.IdentityARN != "" {
				if s := g.identByARN[sub.IdentityARN]; s != nil && s.kind != models.CloudIdentityIAMGroup {
					src = s
				}
			}
			write := func(span loadSpan, source string, ident *loadIdent, ext *loadExternal) {
				state, reason := span.state()
				last := a.run(span.lastCycle(C))
				var sIdent, sExt *uuid.UUID
				if ident != nil {
					sIdent = &ident.id
				} else {
					sExt = &ext.id
					ext.edges++
				}
				id := g.uuid()
				g.rows.add("iga_relationship", id, g.ws, models.RelTypeCanAssume, sIdent, nil, sExt, role.id,
					models.BasisDeclared, state, g.at(span.from, a.k), g.validTo(a, span), last.at, last.id, reason,
					igagraph.CanAssumeKey(source, role.endpoint(), stKey), part, a.conn, stKey, cond, sub.Mechanism,
					g.at(span.from, a.k), last.at)
				g.link("iga_relationship_evidence", id, span, role.obs)
				if span.to == 0 && len(g.h.canAssume) < 60 && ident != nil && ident.acct != role.acct {
					g.h.canAssume = append(g.h.canAssume, id)
				}
			}
			if src != nil {
				if src.life.first > from {
					from = src.life.first
				}
				// A source identity that retires is named by ARN still: its
				// identity-sourced edge ends and an aws_principal edge begins
				// (D-41 rule 3), never re-pointed in place.
				srcEnd := src.life.retired
				to := end
				if srcEnd > 0 && (to == 0 || srcEnd < to) {
					to = srcEnd
				}
				span := loadSpan{from: from, to: to, reason: models.EndedNotSeen}
				if span.to == 0 || span.to > span.from {
					write(span, src.endpoint(), src, nil)
				}
				if srcEnd > 0 && (end == 0 || srcEnd < end) {
					ext := g.externalPrincipal(sub.Issuer, sub.Subject, models.ExternalPrincipalAWSPrincipal, a.run(srcEnd))
					write(loadSpan{from: srcEnd, to: end, reason: models.EndedNotSeen}, ext.key, nil, ext)
				}
				continue
			}
			ext := g.externalPrincipal(sub.Issuer, sub.Subject, sub.Kind, a.run(from))
			write(loadSpan{from: from, to: end, reason: models.EndedNotSeen}, ext.key, nil, ext)
		}
	}
}

// externalPrincipal returns (creating once) the external principal for an issuer and
// subject; one node per workspace however many roles trust it.
func (g *loadGen) externalPrincipal(issuer, subject, kind string, first *loadRun) *loadExternal {
	key := igagraph.ExternalPrincipalKey(issuer, subject)
	if e := g.externals[key]; e != nil {
		if first.at.Before(e.first.at) {
			e.first = first
		}
		return e
	}
	e := &loadExternal{id: g.uuid(), issuer: issuer, subject: subject, mechanism: kind, key: key, first: first}
	g.externals[key] = e
	return e
}

// identityRows writes every identity: cloud_identity (while the identity
// exists), its observation, the graph row, support and lifecycle events, and
// users' access keys.
func (g *loadGen) identityRows() {
	C := g.shape.Cycles
	for _, i := range g.idents {
		a := i.acct
		last := i.life.lastCycle(C)
		attrs := map[string]any{"path": i.path, "unique_id": i.uid}
		pattrs := map[string]any{"path": i.path}
		if i.tags != nil {
			attrs["tags"], pattrs["tags"] = i.tags, i.tags
		}
		if i.boundary != nil {
			attrs["permissions_boundary_arn"], pattrs["permissions_boundary_arn"] = i.boundary.arn, i.boundary.arn
		}
		for k, v := range i.attrs {
			pattrs[k] = v
		}
		var trustDoc any
		trustHash := ""
		if i.kind == models.CloudIdentityIAMRole {
			attrs["has_trust_policy"] = true
			trustDoc = loadJSON(i.trustDoc)
			trustHash = loadHash(string(i.trustDoc))
		}
		surface := map[string]string{models.CloudIdentityIAMRole: models.SurfaceIAMRoles,
			models.CloudIdentityIAMUser: models.SurfaceIAMUsers, models.CloudIdentityIAMGroup: models.SurfaceIAMGroups}[i.kind]
		var cloudRef *uuid.UUID
		if i.life.live() {
			// A gone identity's cloud row was deleted by the collector; its
			// observation keeps the history with its subject SET NULL.
			cloudRef = &i.cloudID
			g.rows.add("cloud_identity", i.cloudID, g.ws, a.conn, i.kind, i.arn, i.name, g.base.Add(-720*time.Hour),
				true, loadMarshal(attrs), last, g.at(i.life.first, a.k), a.run(last).at, a.run(last).at, trustDoc, trustHash, "")
		}
		facts := map[string]any{"kind": i.kind, "name": i.name, "path": i.path, "native_id": i.arn, "unique_id": i.uid}
		if trustDoc != nil {
			facts["trust_document"] = trustDoc
		}
		i.obs = g.observe(a, "identity_id", cloudRef, "iam:GetAccountAuthorizationDetails", surface, i.arn, facts, i.life.first, last)

		lifecycle, reason := i.life.lifecycle()
		g.rows.add("iga_identity_accounts", i.id, g.ws, a.scope, i.name, i.kind, "provider_native", lifecycle,
			models.RollupConfirmed, "aws", i.sourceKey(), models.ContinuityImmutable, i.uid,
			g.at(i.life.first, a.k), a.run(last).at, reason, loadMarshal(pattrs), g.at(i.life.first, a.k), a.run(last).at)
		g.support(a, "identity_account_id", i.id, a.nodePart(models.ObjectIdentity, i.kind, ""), i.life)
		g.events(a, "identity_account_id", i.id, i.life)

		if i.kind == models.CloudIdentityIAMUser && g.chance(0.6) {
			for n := 0; n < 1+g.rng.Intn(2); n++ {
				keyID := fmt.Sprintf("AKIA%c%015d", 'A'+rune(a.k), g.rng.Intn(1_000_000_000))
				state := "active"
				if n == 1 || !i.life.live() {
					state = "revoked"
				}
				used := a.run(last).at.Add(-36 * time.Hour)
				g.rows.add("iga_credentials", g.uuid(), g.ws, i.id, models.CloudSecretAccessKey, "aws", keyID, state, "aws",
					igagraph.Key("aws", i.arn, keyID), models.ContinuityRecognitionOnly, "unknown",
					g.at(i.life.first, a.k), a.run(last).at, &used, g.at(i.life.first, a.k), a.run(last).at)
			}
		}
	}
}

// externalRows writes the external principals once every edge is known.
func (g *loadGen) externalRows() {
	for _, key := range loadSortedKeys(g.externals) {
		e := g.externals[key]
		g.rows.add("iga_external_principal", e.id, g.ws, e.issuer, e.subject, e.mechanism, e.key, e.first.at, g.pubs[len(g.pubs)-1].at)
	}
}

// loadIsService reports whether a principal is an AWS service principal.
func loadIsService(s string) bool { return strings.HasSuffix(s, ".amazonaws.com") }
