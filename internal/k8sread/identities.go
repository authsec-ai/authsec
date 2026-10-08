package k8sread

import (
	"strings"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Identity kinds as the routes spell them (D-113), and the account_kind each
// names. A Kubernetes graph holds three: the ServiceAccounts a sweep lists
// (or a binding names), and the Users and Groups bindings name -- principals
// Kubernetes has no objects for, which the projection still records because
// they hold access (k8sgraph.Project).
const (
	KindServiceAccount = "service_account"
	KindUser           = "user"
	KindGroup          = "group"

	AccountKindUser  = "k8s_user"
	AccountKindGroup = "k8s_group"
)

// AccountKinds is every Kubernetes account kind, in the order a response
// names them.
var AccountKinds = []string{models.K8sAccountKindServiceAccount, AccountKindUser, AccountKindGroup}

// AccountKind maps a route's kind (service_account | user | group, or the
// account kind itself) to the account kind. ok is false for anything else.
func AccountKind(kind string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case KindServiceAccount, models.K8sAccountKindServiceAccount:
		return models.K8sAccountKindServiceAccount, true
	case KindUser, AccountKindUser:
		return AccountKindUser, true
	case KindGroup, AccountKindGroup:
		return AccountKindGroup, true
	}
	return "", false
}

// Identity list paging (D-113): the default keeps the list's old answer to a
// caller that sends limit=500, the console's only call before D-113.
const (
	IdentityDefaultLimit = 500
	IdentityMaxLimit     = 1000
)

// IdentityFilter chooses and positions a page of ListIdentities.
type IdentityFilter struct {
	// Kinds are account kinds (AccountKind). Empty is ServiceAccounts only:
	// the list's contract before D-113.
	Kinds []string
	// Cluster, when set, keeps the identities whose key names that cluster
	// (k8sgraph.ClusterPrefix, as countInto). Namespace keeps a
	// ServiceAccount namespace; a User or Group has none, so a namespace
	// filter never returns one.
	Cluster   string
	Namespace string
	// Limit is clamped to 1..IdentityMaxLimit; <= 0 is IdentityDefaultLimit.
	Limit int
	// After is the position the previous page ended at; nil is the first.
	After *IdentityPosition
}

// IdentityPosition is a row's place in the list's order: anchor, then id.
// The cursor carries it.
type IdentityPosition struct {
	Anchor string
	ID     uuid.UUID
}

// IdentityPage is one page and how many identities the filter matches in all.
type IdentityPage struct {
	Items []Identity
	Total int
	// Next is the last row's position when another page may follow, else nil.
	Next *IdentityPosition
}

// identityWhere is the identity rows a statement reads: a filter, or one id.
type identityWhere struct {
	kinds     []string
	cluster   string
	namespace string
	id        *uuid.UUID
}

// sql is the WHERE over iga_identity_accounts i, and its bind values. Every
// form is bound to the workspace and to Kubernetes identities.
func (w identityWhere) sql(ws uuid.UUID) (string, []any) {
	kinds := w.kinds
	if len(kinds) == 0 {
		kinds = []string{models.K8sAccountKindServiceAccount}
	}
	where := `i.workspace_id = ? AND i.provider = ? AND i.account_kind IN ?`
	args := []any{ws, models.ProviderK8s, kinds}
	if w.cluster != "" {
		prefix := k8sgraph.ClusterPrefix(w.cluster)
		where += ` AND left(i.source_key, length(?)) = ?`
		args = append(args, prefix, prefix)
	}
	if w.namespace != "" {
		where += ` AND COALESCE(i.provider_attrs->>'namespace', '') = ?`
		args = append(args, w.namespace)
	}
	if w.id != nil {
		where += ` AND i.id = ?`
		args = append(args, *w.id)
	}
	return where, args
}

// identityColumns are an identity row's own fields, read from
// iga_identity_accounts i alone. The cluster is the key's second field
// (k8sgraph.Key: k8s <US> cluster <US> ...).
const identityColumns = `
		i.id,
		i.display_name AS anchor,
		COALESCE(i.provider_attrs->>'namespace', '') AS namespace,
		i.lifecycle,
		i.account_kind AS kind,
		COALESCE(NULLIF(i.provider_attrs->>'name', ''), i.display_name) AS name,
		split_part(i.source_key, E'\037', 2) AS cluster,
		i.last_seen_at`

// ListIdentities lists the workspace's Kubernetes identities the filter
// keeps, by anchor (then id), keyset-paged.
//
// The page is chosen FIRST -- filters, order, position, limit, from
// iga_identity_accounts alone -- and the counts are read for that page's
// identities only (fill). That is why the order is the anchor and not the
// grant count: ordering by grants would need every identity's count before
// the first row could be chosen, which is the whole-workspace computation
// this avoids (D-113).
func (q *Query) ListIdentities(f IdentityFilter) (IdentityPage, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = IdentityDefaultLimit
	}
	if limit > IdentityMaxLimit {
		limit = IdentityMaxLimit
	}
	where, args := identityWhere{kinds: f.Kinds, cluster: f.Cluster, namespace: f.Namespace}.sql(q.WS)

	var page IdentityPage
	var total struct{ N int }
	if err := q.tx.Raw(`SELECT count(*) AS n FROM iga_identity_accounts i WHERE `+where, args...).
		Scan(&total).Error; err != nil {
		return page, err
	}
	page.Total = total.N

	if f.After != nil {
		// Row comparison: the ORDER BY's own order, collation included.
		where += ` AND (i.display_name, i.id) > (?, ?)`
		args = append(args, f.After.Anchor, f.After.ID)
	}
	// One more than the page, to know whether another follows.
	args = append(args, limit+1)
	var out []Identity
	if err := q.tx.Raw(`SELECT `+identityColumns+`
		  FROM iga_identity_accounts i
		 WHERE `+where+`
		 ORDER BY i.display_name, i.id
		 LIMIT ?`, args...).Scan(&out).Error; err != nil {
		return page, err
	}
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		page.Next = &IdentityPosition{Anchor: last.Anchor, ID: last.ID}
	}
	if out == nil {
		out = []Identity{}
	}
	if err := q.fill(out); err != nil {
		return page, err
	}
	page.Items = out
	return page, nil
}

// Identity reads one Kubernetes identity of any kind in the workspace, with
// the same fields and counts as its list row. Nil when the workspace has no
// Kubernetes identity with that id.
func (q *Query) Identity(id uuid.UUID) (*Identity, error) {
	where, args := identityWhere{kinds: AccountKinds, id: &id}.sql(q.WS)
	var out []Identity
	if err := q.tx.Raw(`SELECT `+identityColumns+`
		  FROM iga_identity_accounts i
		 WHERE `+where, args...).Scan(&out).Error; err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	if err := q.fill(out[:1]); err != nil {
		return nil, err
	}
	return &out[0], nil
}

// fill sets the counts of the identities given, reading only theirs: grants,
// stale and wildcard from their access rows (countsFor -- the access route's
// own rows, so an identity's grants and stale equal its access summary's
// partial and stale, D-112: for a ServiceAccount its own grants and its
// groups', for a User or Group its own), and a group's live members.
func (q *Query) fill(ids []Identity) error {
	if len(ids) == 0 {
		return nil
	}
	holders := make([]uuid.UUID, 0, len(ids))
	var groups []uuid.UUID
	for _, i := range ids {
		holders = append(holders, i.ID)
		if i.Kind == AccountKindGroup {
			groups = append(groups, i.ID)
		}
	}
	counts, err := q.countsFor(holders)
	if err != nil {
		return err
	}
	members := map[uuid.UUID]int{}
	if len(groups) > 0 {
		var rows []struct {
			ID uuid.UUID
			N  int
		}
		if err := q.tx.Raw(`
			SELECT m.target_identity_account_id AS id, count(*) AS n
			  FROM iga_relationship m
			 WHERE m.workspace_id = ? AND m.relationship_type = 'member_of'
			   AND m.target_identity_account_id IN ?
			   AND m.state IN ('current', 'stale')
			 GROUP BY m.target_identity_account_id`, q.WS, groups).Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			members[r.ID] = r.N
		}
	}
	for i := range ids {
		c := counts[ids[i].ID]
		ids[i].Grants, ids[i].Stale, ids[i].Wildcard = c.Grants, c.Stale, c.Wildcard
		if ids[i].Kind == AccountKindGroup {
			n := members[ids[i].ID]
			ids[i].Members = &n
		}
	}
	return nil
}
