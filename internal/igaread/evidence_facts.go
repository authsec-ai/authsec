package igaread

// Supporting facts and freshness for /evidence (§5.3, D-23, D-24, D-66,
// D-80). Every read here is ONE statement for all the claims of the request
// that need it: one per evidence junction (§5.6 "junction -> observation, one
// query per edge type"), one for every object observation, one for Access
// Advisor, one for stale_since.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// What a linked observation evidences, from its call and surface (§4.8's
// table). Collectors key every observation by (subject kind,
// subject_native_id) only, so a holder's credential report is linked to every
// grant the holder has; classifying by call and surface is what keeps it off
// them (D-24 "keep only source APIs that bear on the claim type").
const (
	factRoleEntry      = "role_entry"      // a role's authorization-details entry (attachments, trust document)
	factUserEntry      = "user_entry"      // a user's entry (attachments, groups)
	factGroupEntry     = "group_entry"     // a group's entry (attachments)
	factPolicyVersion  = "policy_version"  // a policy version's observation (subject policy_id)
	factWorkload       = "workload"        // a workload's own listing or detail read
	factPodAssociation = "pod_association" // an EKS Pod Identity association
)

// authDetailsAPI is the call every role, user and group entry is recorded
// under (T3.1).
const authDetailsAPI = "iam:GetAccountAuthorizationDetails"

// podIdentityAPI is the call a pod-identity association is recorded under.
const podIdentityAPI = "eks:DescribePodIdentityAssociation"

// activityAPI is the Access Advisor read (§2.14.8).
const activityAPI = "iam:GetServiceLastAccessedDetails"

// workloadSurfacePrefixes are the per-service surfaces a workload's own
// observation is stamped with (<prefix>:<region>).
var workloadSurfacePrefixes = []string{
	models.SurfaceLambdaPrefix, models.SurfaceECSPrefix, models.SurfaceEC2Prefix,
	models.SurfaceBedrockAgentsPrefix, models.SurfaceBedrockAgentCorePrefix, models.SurfaceAgentCoreGatewaysPrefix,
}

// classifyObservation names what an observation evidences, or "" when it
// evidences no configuration this route shows (a credential report, activity).
func classifyObservation(sourceAPI, surface string) string {
	switch {
	case surface == models.SurfaceIAMPolicies:
		return factPolicyVersion
	case sourceAPI == authDetailsAPI && surface == models.SurfaceIAMRoles:
		return factRoleEntry
	case sourceAPI == authDetailsAPI && surface == models.SurfaceIAMUsers:
		return factUserEntry
	case sourceAPI == authDetailsAPI && surface == models.SurfaceIAMGroups:
		return factGroupEntry
	case sourceAPI == podIdentityAPI && surface == models.SurfaceEKSPodIdentity:
		return factPodAssociation
	}
	if prefix, _, ok := strings.Cut(surface, ":"); ok && contains(workloadSurfacePrefixes, prefix) {
		return factWorkload
	}
	return ""
}

func isHolderEntry(kind string) bool {
	return kind == factRoleEntry || kind == factUserEntry || kind == factGroupEntry
}

// factMaker composes a claim's fact for one kind of linked observation, or
// reports that the kind does not bear on the claim.
type factMaker func(kind string) (EvidenceFact, bool)

// grantFactsFor: the holder's entry (it lists the attachment) and the policy
// version's observation (it holds the statement) -- §4.8's two for a grant.
func grantFactsFor(r grantRow, st *evStatement, pos, excl []evTarget) factMaker {
	pol := &EvidencePolicy{Ref: R(RefPolicy, st.PolicyID), Name: st.PolicyName, Kind: st.PolicyKind}
	allows := fmt.Sprintf("Statement %s allows %s on %s", st.label(), actionsPhrase(st.text), targetsPhrase(pos, excl, false))
	return func(kind string) (EvidenceFact, bool) {
		switch {
		case isHolderEntry(kind):
			return EvidenceFact{Fact: holderAttachmentFact(r.AssignmentKind, r.HolderName, r.PolicyName)}, true
		case kind == factPolicyVersion:
			return EvidenceFact{Fact: allows, rank: 2, PolicyVersion: strPtr(st.VersionID),
				StatementExcerpt: excerpt(st.NativeRights), Policy: pol, Statement: stmtRef(st)}, true
		}
		return EvidenceFact{}, false
	}
}

/* --------------------------------- junctions ------------------------------- */

// evJunction is one evidence junction table (032, 036) and its edge column.
type evJunction struct{ table, column string }

var (
	tableAccessEvidence       = evJunction{"iga_access_edge_evidence", "access_edge_id"}
	tableAssignmentEvidence   = evJunction{"iga_assignment_evidence", "assignment_id"}
	tableRelationshipEvidence = evJunction{"iga_relationship_evidence", "relationship_id"}
)

// junctionWant is one edge whose supporting observations a claim wants: the
// edge's last confirming run filters the links (D-24) and is each fact's run.
type junctionWant struct {
	claim *evClaim
	edge  uuid.UUID
	run   *uuid.UUID
	at    *time.Time
	make  factMaker
}

// wantJunction queues one edge's links for a claim. run and at are the
// EDGE's last confirming run and time: the claim's own for an edge claim, each
// trusting edge's for an external principal (D-24).
func (l *claimLoader) wantJunction(j evJunction, c *evClaim, edge uuid.UUID, run *uuid.UUID, at *time.Time, make factMaker) {
	if !l.opts.facts {
		return
	}
	if l.junction == nil {
		l.junction = map[string][]junctionWant{}
	}
	l.junction[j.table+"|"+j.column] = append(l.junction[j.table+"|"+j.column],
		junctionWant{claim: c, edge: edge, run: run, at: at, make: make})
}

// obsRow is one observation as the fact queries read it.
type obsRow struct {
	K           int
	EdgeID      uuid.UUID
	ObsID       uuid.UUID
	SourceAPI   string
	Surface     string
	ConnectorID uuid.UUID
	Region      string
	IdentityID  *uuid.UUID
	Raw         json.RawMessage
}

// runJunction reads one junction for every edge wanted: the 'supports' links
// whose observation was last confirmed by the edge's own last confirming run
// or a LATER run of the same connector (D-24). A link whose observation a
// newer run of that connector no longer confirmed -- the previous policy
// version, say -- is dropped; the junction is never pruned, so without this
// every version the statement ever had would be shown as support. An edge
// with no recorded run (its run row deleted) keeps its links: there is
// nothing to date them by.
func (l *claimLoader) runJunction(key string, wants []junctionWant) error {
	table, column, _ := strings.Cut(key, "|")
	values := []string{}
	args := []any{}
	seen := map[uuid.UUID]bool{}
	for _, w := range wants {
		if seen[w.edge] {
			continue
		}
		seen[w.edge] = true
		values = append(values, "(?::uuid, ?::uuid)")
		args = append(args, w.edge, w.run)
	}
	args = append(args, l.q.WS)
	var rows []obsRow
	if err := l.q.DB().Raw(`SELECT j.`+column+` AS edge_id, o.id AS obs_id, o.source_api, o.surface, o.connector_id,
	                               COALESCE(o.sanitized_facts->>'region', '') AS region, o.identity_id,
	                               `+l.rawColumn()+` AS raw
	                          FROM (VALUES `+strings.Join(values, ", ")+`) AS v(edge, run)
	                          JOIN `+table+` j ON j.`+column+` = v.edge
	                          JOIN cloud_observation o ON o.workspace_id = j.workspace_id AND o.id = j.observation_id
	                          LEFT JOIN cloud_scan_run cr ON cr.workspace_id = j.workspace_id AND cr.id = v.run
	                          LEFT JOIN cloud_scan_run lr ON lr.workspace_id = o.workspace_id AND lr.id = o.last_confirmed_run_id
	                         WHERE j.workspace_id = ? AND j.relation = 'supports'
	                           AND (v.run IS NULL OR (lr.connector_id = cr.connector_id AND lr.generation >= cr.generation))
	                         ORDER BY j.`+column+`, o.id`, args...).Scan(&rows).Error; err != nil {
		return err
	}
	byEdge := map[uuid.UUID][]junctionWant{}
	for _, w := range wants {
		byEdge[w.edge] = append(byEdge[w.edge], w)
	}
	for _, o := range rows {
		kind := classifyObservation(o.SourceAPI, o.Surface)
		for _, w := range byEdge[o.EdgeID] {
			f, ok := w.make(kind)
			if !ok {
				continue
			}
			l.addFact(w.claim, f, o, w.run, w.at)
		}
	}
	return nil
}

// rawColumn selects sanitized_facts only when include=raw asked for it: the
// stored record is the route's one exposure (§5.3), and never read otherwise.
func (l *claimLoader) rawColumn() string {
	if l.opts.raw {
		return "o.sanitized_facts"
	}
	return "NULL::jsonb"
}

// addFact fills a composed fact with its observation's call, account and
// region, and the claim's run and confirmation time (D-24), once per
// observation and sentence.
func (l *claimLoader) addFact(c *evClaim, f EvidenceFact, o obsRow, run *uuid.UUID, at *time.Time) {
	for _, have := range c.facts {
		if have.obs != nil && *have.obs == o.ObsID && have.Fact == f.Fact {
			return
		}
	}
	f.SourceAPI = o.SourceAPI
	f.AccountID = nil
	if conn := l.accts.Connector(o.ConnectorID); conn != nil {
		f.AccountID = conn.AccountID
	}
	f.Region = nullIfBlank(o.Region)
	f.ObservedInRun = RPtr(RefScanRun, run)
	f.LastConfirmedAt = TS(at)
	id := o.ObsID
	f.obs = &id
	if l.opts.raw && len(o.Raw) > 0 {
		f.raw = o.Raw
	}
	c.facts = append(c.facts, f)
}

/* ---------------------------- object observations -------------------------- */

// obsAnchor is one object observation a presence (or target) claim wants:
// in one connector, confirmed as of one support row's last run, on one
// surface, by its subject_native_id -- exact, or (workloads) the ARN's final
// segment, which is what a collector that stores a bare id (EC2, early
// Bedrock rows) wrote.
type obsAnchor struct {
	claim     *evClaim
	connector uuid.UUID
	run       uuid.UUID
	at        *time.Time
	native    string
	suffix    bool
	surface   string
	api       string
	make      func(o obsRow) EvidenceFact
	// identity marks an identity's own entry, whose cloud identity keys its
	// Access Advisor rows.
	identity bool
}

func (l *claimLoader) wantAnchor(a obsAnchor) {
	if !l.opts.facts || a.native == "" {
		return
	}
	l.anchors = append(l.anchors, a)
}

// wantIdentityObservations: an identity's authorization-details entry in
// each connector that supports it.
func (l *claimLoader) wantIdentityObservations(c *evClaim, ss []evSupport, row *nodeRow) {
	surface := models.SurfaceIAMRoles
	switch row.Kind {
	case models.CloudIdentityIAMUser:
		surface = models.SurfaceIAMUsers
	case models.CloudIdentityIAMGroup:
		surface = models.SurfaceIAMGroups
	}
	name := identityKindWords(row.Kind) + " " + row.Name
	for _, s := range ss {
		if s.LastConfirmedRunID == nil {
			continue
		}
		label := l.accountLabel(s.ConnectorID)
		l.wantAnchor(obsAnchor{
			claim: c, connector: s.ConnectorID, run: *s.LastConfirmedRunID, at: s.LastConfirmedAt,
			native: NativeOfKey(row.SourceKey), surface: surface, api: authDetailsAPI, identity: true,
			make: func(obsRow) EvidenceFact {
				return EvidenceFact{Fact: fmt.Sprintf("%s is listed in the authorization details of %s", name, label)}
			},
		})
	}
}

// wantWorkloadObservations: a workload's own observation in each connector
// that supports it, on the per-service surface igagraph partitions it by.
func (l *claimLoader) wantWorkloadObservations(c *evClaim, ss []evSupport, row *nodeRow) {
	name := runtimeKindWords(row.Kind) + " " + row.Name
	for _, s := range ss {
		if s.LastConfirmedRunID == nil {
			continue
		}
		part, ok := partitionOf(models.ObjectWorkload, row.Kind, row.Region, uuid.Nil, s.ConnectorID)
		if !ok || len(part.RequiredSurfaces) == 0 {
			continue
		}
		surface := part.RequiredSurfaces[0]
		l.wantAnchor(obsAnchor{
			claim: c, connector: s.ConnectorID, run: *s.LastConfirmedRunID, at: s.LastConfirmedAt,
			native: NativeOfKey(row.SourceKey), suffix: true, surface: surface,
			make: func(o obsRow) EvidenceFact {
				return EvidenceFact{Fact: fmt.Sprintf("%s is listed by %s", name, o.SourceAPI)}
			},
		})
	}
}

// wantPolicyObservations: a policy version's observation in each connector
// that supports the claim's node, keyed as the collector keys it
// (cloud_policy.native_id: the ARN; "inline:<holder ARN>:<name>" inline).
func (l *claimLoader) wantPolicyObservations(c *evClaim, ss []evSupport, kind, nativeRef, sourceKey string, make func() EvidenceFact) {
	native := policyNativeID(kind, nativeRef, sourceKey)
	for _, s := range ss {
		if s.LastConfirmedRunID == nil {
			continue
		}
		l.wantAnchor(obsAnchor{
			claim: c, connector: s.ConnectorID, run: *s.LastConfirmedRunID, at: s.LastConfirmedAt,
			native: native, surface: models.SurfaceIAMPolicies,
			make: func(obsRow) EvidenceFact { return make() },
		})
	}
}

// policyNativeID is the subject_native_id a policy version's observation
// carries: the managed policy's ARN, or for an inline policy the holder ARN
// and name its source key holds (igagraph.PolicyKey).
func policyNativeID(kind, nativeRef, sourceKey string) string {
	if kind != "inline" {
		return nativeRef
	}
	parts := strings.Split(sourceKey, "\x1f")
	if len(parts) == 4 && parts[0] == "aws" && parts[1] == "inline" {
		return "inline:" + parts[2] + ":" + parts[3]
	}
	return ""
}

// wantResourceNamers queues a resource presence claim: its facts are the
// policy versions of the statements that name it (a reference has no
// observation of its own).
func (l *claimLoader) wantResourceNamers(c *evClaim, resource uuid.UUID) {
	if !l.opts.facts {
		return
	}
	if l.namedByRes == nil {
		l.namedByRes = map[uuid.UUID][]*evClaim{}
	}
	l.namedByRes[resource] = append(l.namedByRes[resource], c)
}

// resourceNamers turns each queued resource into policy-version anchors: for
// every support row, the statements naming the resource (at most
// LimitationRefCap per resource), in that row's connector.
func (l *claimLoader) resourceNamers() error {
	if len(l.namedByRes) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(l.namedByRes))
	for id := range l.namedByRes {
		ids = append(ids, id)
	}
	var rows []struct {
		ResourceID uuid.UUID
		Mode       string
		StatementRow
	}
	if err := l.q.DB().Raw(`SELECT x.resource_id, x.mode, x.statement_id, x.sid, x.statement_index, x.effect, x.negated,
	                               x.conditional, x.native_rights, x.policy_id, x.policy_name, x.policy_kind,
	                               x.policy_version_id, x.revision_version_id, x.policy_native_ref, x.policy_source_key
	                          FROM (SELECT t.resource_id, t.target_mode AS mode, `+stmtColumns+`,
	                                       row_number() OVER (PARTITION BY t.resource_id ORDER BY p.display_name, e.statement_index, e.id) AS n
	                                  FROM iga_entitlement_target t
	                                  JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
	                                   AND e.provider = 'aws' AND e.lifecycle = ?
	                                  `+stmtJoins+`
	                                 WHERE t.workspace_id = ? AND t.resource_id IN ?) x
	                         WHERE x.n <= ?`,
		models.IGALifecycleActive, l.q.WS, uniqueIDs(ids), LimitationRefCap).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		st := r.statement()
		for _, c := range l.namedByRes[r.ResourceID] {
			verb := "names"
			if r.Mode == models.TargetNotResource {
				verb = "excludes"
			}
			pol := &EvidencePolicy{Ref: R(RefPolicy, st.PolicyID), Name: st.PolicyName, Kind: st.PolicyKind}
			text := fmt.Sprintf("Statement %s of %s %s this reference", st.label(), st.PolicyName, verb)
			for _, s := range c.supports {
				if s.LastConfirmedRunID == nil {
					continue
				}
				l.wantAnchor(obsAnchor{
					claim: c, connector: s.ConnectorID, run: *s.LastConfirmedRunID, at: s.LastConfirmedAt,
					native: policyNativeID(r.PolicyKind, r.PolicyNativeRef, r.PolicySourceKey), surface: models.SurfaceIAMPolicies,
					make: func(obsRow) EvidenceFact {
						return EvidenceFact{Fact: text, rank: 2, PolicyVersion: strPtr(st.VersionID),
							StatementExcerpt: excerpt(st.NativeRights), Policy: pol, Statement: stmtRef(st)}
					},
				})
			}
		}
	}
	return nil
}

// runAnchors reads every queued object observation in one statement. The run
// is walked through cloud_scan_run so the lookup rides
// idx_cloud_observation_last_confirmed_run: observations last confirmed by the
// support row's run or a later run of its connector (the D-24 rule).
func (l *claimLoader) runAnchors() ([]obsRow, error) {
	if len(l.anchors) == 0 {
		return nil, nil
	}
	values := make([]string, 0, len(l.anchors))
	args := make([]any, 0, 7*len(l.anchors)+1)
	for k, a := range l.anchors {
		values = append(values, "(?::int, ?::uuid, ?::uuid, ?::text, ?::bool, ?::text, ?::text)")
		args = append(args, k, a.connector, a.run, a.native, a.suffix, a.surface, a.api)
	}
	args = append(args, l.q.WS)
	var rows []obsRow
	if err := l.q.DB().Raw(`SELECT v.k, o.id AS obs_id, o.source_api, o.surface, o.connector_id,
	                               COALESCE(o.sanitized_facts->>'region', '') AS region, o.identity_id,
	                               `+l.rawColumn()+` AS raw
	                          FROM (VALUES `+strings.Join(values, ", ")+`) AS v(k, cid, rid, native, suffix, surface, api)
	                          JOIN cloud_scan_run cr ON cr.id = v.rid
	                          JOIN cloud_scan_run lr ON lr.workspace_id = cr.workspace_id AND lr.connector_id = v.cid
	                           AND lr.generation >= cr.generation
	                          JOIN cloud_observation o ON o.workspace_id = lr.workspace_id AND o.last_confirmed_run_id = lr.id
	                           AND o.connector_id = v.cid AND o.surface = v.surface
	                           AND (o.subject_native_id = v.native
	                                OR (v.suffix AND o.subject_native_id <> ''
	                                    AND right(v.native, length(o.subject_native_id) + 1)
	                                        IN ('/' || o.subject_native_id, ':' || o.subject_native_id)))
	                         WHERE cr.workspace_id = ? AND (v.api = '' OR o.source_api = v.api)
	                         ORDER BY v.k, o.id`, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

/* ------------------------------ Access Advisor ----------------------------- */

// usageWant is an identity entry observation whose cloud identity's Access
// Advisor rows the claim shows.
type usageWant struct {
	claim *evClaim
	obs   uuid.UUID
	run   uuid.UUID
	at    *time.Time
}

// runUsage reads the Access Advisor rows (cloud_usage, source
// service_last_accessed) of the identities whose entries were found, through
// the entry's own cloud identity (the observation's subject) -- never by name.
// Only rows a run at or before the support row's run last wrote: a row a
// newer, unpublished run rewrote describes a read the revision does not hold
// (D-25).
//
// The wording is §2.14.8's: an attempt, not an outcome, and "no attempt
// reported in the available tracking period" -- never "used" or "never used".
func (l *claimLoader) runUsage() error {
	if len(l.usage) == 0 {
		return nil
	}
	values := make([]string, 0, len(l.usage))
	args := []any{}
	for k, u := range l.usage {
		values = append(values, "(?::int, ?::uuid, ?::uuid)")
		args = append(args, k, u.obs, u.run)
	}
	args = append(args, l.q.WS, models.UsageSourceServiceLastAccessed)
	var rows []struct {
		K           int
		UsageID     uuid.UUID
		Service     string
		LastUsedAt  *time.Time
		ConnectorID uuid.UUID
	}
	if err := l.q.DB().Raw(`SELECT v.k, u.id AS usage_id, u.service, u.last_used_at, u.connector_id
	                          FROM (VALUES `+strings.Join(values, ", ")+`) AS v(k, obs, rid)
	                          JOIN cloud_observation o ON o.id = v.obs
	                          JOIN cloud_scan_run cr ON cr.workspace_id = o.workspace_id AND cr.id = v.rid
	                          JOIN cloud_usage u ON u.workspace_id = o.workspace_id AND u.identity_id = o.identity_id
	                           AND u.connector_id = o.connector_id AND u.last_seen_generation <= cr.generation
	                         WHERE o.workspace_id = ? AND u.source = ?
	                         ORDER BY v.k, u.service, u.id`, args...).Scan(&rows).Error; err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range rows {
		w := l.usage[r.K]
		key := w.claim.ref.String() + "|" + r.UsageID.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		text := fmt.Sprintf("Access Advisor reports no attempt on %s in the available tracking period", r.Service)
		if r.LastUsedAt != nil {
			text = fmt.Sprintf("Access Advisor reports an authenticated attempt on %s, last at %s (an attempt, not an outcome)",
				r.Service, r.LastUsedAt.UTC().Format(time.RFC3339))
		}
		f := EvidenceFact{SourceAPI: activityAPI, Region: nil, Fact: text, rank: 3,
			ObservedInRun: R(RefScanRun, w.run), LastConfirmedAt: TS(w.at)}
		if conn := l.accts.Connector(r.ConnectorID); conn != nil {
			f.AccountID = conn.AccountID
		}
		w.claim.facts = append(w.claim.facts, f)
		w.claim.lim.activity = true
	}
	return nil
}

/* --------------------------------- driver ---------------------------------- */

// loadFacts runs every queued fact read.
func (l *claimLoader) loadFacts() error {
	for _, j := range []evJunction{tableAccessEvidence, tableAssignmentEvidence, tableRelationshipEvidence} {
		key := j.table + "|" + j.column
		if wants := l.junction[key]; len(wants) > 0 {
			if err := l.runJunction(key, wants); err != nil {
				return err
			}
		}
	}
	if err := l.resourceNamers(); err != nil {
		return err
	}
	rows, err := l.runAnchors()
	if err != nil {
		return err
	}
	for _, o := range rows {
		if o.K < 0 || o.K >= len(l.anchors) {
			continue
		}
		a := l.anchors[o.K]
		run := a.run
		l.addFact(a.claim, a.make(o), o, &run, a.at)
		if a.identity && o.IdentityID != nil {
			l.usage = append(l.usage, usageWant{claim: a.claim, obs: o.ObsID, run: a.run, at: a.at})
		}
	}
	return l.runUsage()
}

/* -------------------------------- stale_since ------------------------------ */

// loadStaleSince dates every stale claim (D-23): the published_at of the
// first publication of the claim's connector with a rev above that of the
// publication of the claim's last confirming run -- the first revision that
// no longer confirmed it. Runs and revisions, never timestamps compared. A
// claim whose last run has no publication stays null (not known).
func loadStaleSince(q *Query, claims []*evClaim) error {
	var want []*evClaim
	for _, c := range claims {
		if c != nil && c.state == StateStale && c.anchorRun != nil && !containsClaim(want, c) {
			want = append(want, c)
		}
	}
	if len(want) == 0 || q.Rev == nil {
		return nil
	}
	values := make([]string, 0, len(want))
	args := []any{q.Rev.Rev}
	for k, c := range want {
		values = append(values, "(?::int, ?::uuid)")
		args = append(args, k, *c.anchorRun)
	}
	args = append(args, q.WS)
	var rows []struct {
		K     int
		Since *time.Time
	}
	if err := q.DB().Raw(`SELECT v.k,
	                             (SELECT p2.published_at
	                                FROM iga_publication p2
	                                JOIN cloud_scan_run r2 ON r2.workspace_id = p2.workspace_id AND r2.id = p2.scan_run_id
	                               WHERE p2.workspace_id = p1.workspace_id AND r2.connector_id = r1.connector_id
	                                 AND p2.rev > p1.rev AND p2.rev <= ?
	                               ORDER BY p2.rev LIMIT 1) AS since
	                        FROM (VALUES `+strings.Join(values, ", ")+`) AS v(k, rid)
	                        JOIN iga_publication p1 ON p1.scan_run_id = v.rid
	                        JOIN cloud_scan_run r1 ON r1.workspace_id = p1.workspace_id AND r1.id = p1.scan_run_id
	                       WHERE p1.workspace_id = ?`, args...).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		if r.K >= 0 && r.K < len(want) {
			want[r.K].staleSince = r.Since
		}
	}
	return nil
}

func containsClaim(cs []*evClaim, c *evClaim) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

func (l *claimLoader) accountLabel(connector uuid.UUID) string {
	if c := l.accts.Connector(connector); c != nil {
		if c.Label != c.AccountID {
			return fmt.Sprintf("%s (%s)", c.Label, c.AccountID)
		}
		return c.AccountID
	}
	return "an unknown account"
}

// shortDigest is a stable short digest for group keys.
func shortDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
