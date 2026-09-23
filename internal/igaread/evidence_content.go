package igaread

// A statement's content as of a run (§2.6 "statement revisions", §4.9; 036
// iga_statement_revision; P2-DECISIONS D-24).
//
// A Sid-keyed statement keeps its row when its content is revised: the row's
// native_rights and target set are rewritten to the NEW content, and the old
// content survives only as a closed iga_statement_revision. So every claim
// that describes a statement -- a grant's sentence and limitations, the
// statement excerpt of a policy-version fact -- must read the content that was
// declared when the claim's (or the fact's) run last confirmed it, never the
// row's current content: a grant that ended before an edit would otherwise be
// described with actions it never had, and a support row of another account
// that has not re-read the policy since would be paired with a document it
// never saw.
//
// "As of a run" is decided by publications, never by comparing timestamps
// (D-23's rule): the revision whose first_seen_run published at the highest
// rev at or below the rev the claim's run published at. Only when the claim's
// run has no publication (its row was deleted, which a published run's cannot
// be) is the revision chosen by time. A statement with no revision
// (content-keyed: its content IS its identity, so it never changes) or whose
// revision as of the run carries the current content hash is described by the
// row itself.

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// contentWant asks for one statement's content as of one run (and, only when
// that run has no publication, the time it confirmed the claim).
type contentWant struct {
	stmt uuid.UUID
	run  *uuid.UUID
	at   *time.Time
}

// stmtContent is a statement's content from an EARLIER revision -- what it
// declared as of the run asked about -- with the targets that text names,
// resolved to their references the way the projector keys them.
type stmtContent struct {
	raw     json.RawMessage
	text    statementText
	effect  string
	targets []evTarget
}

// applyTo returns a copy of st describing this content. The revision records
// the statement verbatim but not its position in the document, which may have
// moved since, so the 1-based index is not claimed (null, D-84); the Sid --
// which a revised statement always has, being Sid-keyed -- still labels it.
func (h *stmtContent) applyTo(st *evStatement) *evStatement {
	out := *st
	out.NativeRights = h.raw
	out.text = h.text
	out.Index = nil
	out.Negated = len(h.text.NotActions) > 0 || len(h.text.NotResources) > 0
	out.Conditional = hasCondition(h.text.Condition)
	if h.effect != "" {
		out.Effect = h.effect
	}
	return &out
}

// names reports whether this content names t in t's mode: a target claim, or a
// resource's namer, stands on a run only if the content that run confirmed
// named it.
func (h *stmtContent) names(t evTarget) bool {
	for _, x := range h.targets {
		if x.Mode != t.Mode {
			continue
		}
		if (t.ResourceID != uuid.Nil && x.ResourceID == t.ResourceID) || (t.Text != "" && x.Text == t.Text) {
			return true
		}
	}
	return false
}

// contentTarget is one reference a statement's text names, in the order and
// modes projectTargets writes them.
type contentTarget struct {
	text, mode string
	ordinal    int
}

// contentTargets mirrors igagraph's projectTargets: Resource entries are
// targets, NotResource entries exclusions, and a NotResource statement with no
// Resource is scoped by the implicit "*" selector.
func contentTargets(t statementText) []contentTarget {
	var out []contentTarget
	for i, r := range t.Resources {
		out = append(out, contentTarget{r, models.TargetResource, i})
	}
	for i, r := range t.NotResources {
		out = append(out, contentTarget{r, models.TargetNotResource, i})
	}
	if len(t.NotResources) > 0 && len(t.Resources) == 0 {
		out = append(out, contentTarget{"*", models.TargetResource, 0})
	}
	return out
}

// contentAsOf answers every want in two statements: the revisions (one per
// want) and the references their texts name. The result is aligned with wants:
// nil where the statement's current row already describes the content as of
// that run.
func contentAsOf(q *Query, wants []contentWant) ([]*stmtContent, error) {
	out := make([]*stmtContent, len(wants))
	if len(wants) == 0 {
		return out, nil
	}
	// One VALUES row per distinct (statement, run, time).
	type key struct {
		stmt, run uuid.UUID
		at        int64
	}
	slot := map[key]int{}
	var distinct []contentWant
	of := make([]int, len(wants))
	for i, w := range wants {
		k := key{stmt: w.stmt}
		if w.run != nil {
			k.run = *w.run
		}
		if w.at != nil {
			k.at = w.at.UnixNano()
		}
		n, ok := slot[k]
		if !ok {
			n = len(distinct)
			slot[k] = n
			distinct = append(distinct, w)
		}
		of[i] = n
	}
	values := make([]string, 0, len(distinct))
	args := make([]any, 0, 4*len(distinct)+1)
	for k, w := range distinct {
		values = append(values, "(?::int, ?::uuid, ?::uuid, ?::timestamptz)")
		args = append(args, k, w.stmt, w.run, w.at)
	}
	args = append(args, q.WS)
	var rows []struct {
		K         int
		Statement json.RawMessage
	}
	// DISTINCT ON picks, per want, the latest revision that had begun as of
	// the want's run; it is returned only when its content differs from the
	// row's.
	if err := q.DB().Raw(`SELECT x.k, x.statement FROM (
	                        SELECT DISTINCT ON (v.k) v.k, sr.statement, sr.content_hash <> e.content_hash AS differs
	                          FROM (VALUES `+strings.Join(values, ", ")+`) AS v(k, stmt, run, at)
	                          JOIN iga_entitlements e ON e.workspace_id = ? AND e.id = v.stmt AND e.provider = 'aws'
	                          LEFT JOIN iga_publication pc ON pc.workspace_id = e.workspace_id AND pc.scan_run_id = v.run
	                          JOIN iga_statement_revision sr ON sr.workspace_id = e.workspace_id AND sr.entitlement_id = e.id
	                          LEFT JOIN iga_publication pr ON pr.workspace_id = sr.workspace_id AND pr.scan_run_id = sr.first_seen_run_id
	                         WHERE CASE WHEN pc.rev IS NOT NULL THEN pr.rev <= pc.rev
	                                    ELSE v.at IS NOT NULL AND sr.valid_from <= v.at END
	                         ORDER BY v.k, pr.rev DESC NULLS LAST, sr.valid_from DESC, sr.id) x
	                       WHERE x.differs`, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return out, nil
	}

	byK := map[int]*stmtContent{}
	var keys []string
	for _, r := range rows {
		var m map[string]json.RawMessage
		if json.Unmarshal(r.Statement, &m) != nil || len(m) == 0 {
			// A revision that recorded no statement cannot say what was
			// declared; the row stays the description. (The projector always
			// records the verbatim statement, so this is a legacy guard.)
			continue
		}
		h := &stmtContent{raw: r.Statement, text: parseStatementText(r.Statement)}
		var effect string
		if json.Unmarshal(m["Effect"], &effect) == nil {
			h.effect = strings.ToLower(effect)
		}
		for _, t := range contentTargets(h.text) {
			keys = append(keys, igagraph.ResourceRefKey(t.text))
		}
		byK[r.K] = h
	}
	if len(byK) == 0 {
		return out, nil
	}

	// The references those texts name, by the key the projector writes them
	// under (igagraph.ResourceRefKey): the live row, else the latest retired.
	var refs []struct {
		SourceKey        string
		ResourceID       uuid.UUID
		Text             string
		ResourceKind     string
		Reference        string
		AccountID        string
		AccountConnected bool
	}
	if len(keys) > 0 {
		if err := q.DB().Raw(`SELECT DISTINCT ON (r.source_key) r.source_key, r.id AS resource_id, r.display_name AS text,
		                             r.resource_kind, COALESCE(r.provider_attrs->>'reference', '') AS reference,
		                             `+ResourceAccountSQL+` AS account_id,
		                             `+ResourceAccountConnectedSQL+` AS account_connected
		                        FROM iga_resources r
		                       WHERE r.workspace_id = ? AND r.provider = 'aws' AND r.source_key IN ?
		                       ORDER BY r.source_key, (r.lifecycle <> ?) DESC, r.first_seen_at DESC, r.id`,
			q.WS, uniqueStrings(keys), models.IGALifecycleRetired).Scan(&refs).Error; err != nil {
			return nil, err
		}
	}
	byKey := make(map[string]int, len(refs))
	for i, r := range refs {
		byKey[r.SourceKey] = i
	}
	for k, h := range byK {
		stmt := distinct[k].stmt
		for _, ct := range contentTargets(h.text) {
			t := evTarget{StatementID: stmt, Mode: ct.mode, Ordinal: ct.ordinal, Text: ct.text}
			if i, ok := byKey[igagraph.ResourceRefKey(ct.text)]; ok {
				r := refs[i]
				t.ResourceID, t.Text, t.ResourceKind, t.Reference = r.ResourceID, r.Text, r.ResourceKind, r.Reference
				t.AccountID, t.AccountConnected = r.AccountID, r.AccountConnected
			}
			h.targets = append(h.targets, t)
		}
	}
	for i := range wants {
		out[i] = byK[of[i]]
	}
	return out, nil
}

// resolvedTargets keeps the targets that name a reference row. Every text a
// statement ever named was written as a reference, and references are retired,
// never deleted, so an earlier content's target always resolves; one that did
// not would have no ref for a limitation to list, and still names its text in
// the sentence.
func resolvedTargets(ts []evTarget) []evTarget {
	out := make([]evTarget, 0, len(ts))
	for _, t := range ts {
		if t.ResourceID != uuid.Nil {
			out = append(out, t)
		}
	}
	return out
}

func uniqueStrings(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
