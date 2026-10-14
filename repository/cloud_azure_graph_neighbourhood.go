package repositories

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* cloud_azure_graph_neighbourhood.go answers "what is this node connected
   to?" over the Azure slice of the IGA graph, one hop at a time -- the read
   behind an access graph that starts on one object and expands on request,
   the way the AWS graph tab does, rather than drawing the whole estate.

   Refs name nodes as "<type>:<id>":
     identity:<iga id>   object:<Entra object id>   resource:<iga id>
     workload:<iga id>   external:<iga id>          scope:<scope path>
   A scope node stands for what a grant reaches when it names no single
   resource: the directory, a subscription, a resource group, the tenant root.

   Every edge kind is capped and the most sensitive grants come first, so a
   group like "All Users" or an app with hundreds of delegated permissions
   says how many more there are instead of flooding the canvas. Only live
   rows: ended grants and relationships are history, not access. */

// ErrGraphNodeNotFound is a ref that names nothing live in the graph.
var ErrGraphNodeNotFound = errors.New("graph node not found")

// azureGraphEdgeCap bounds each edge kind on one node.
const azureGraphEdgeCap = 40

// AzureGraphNode is one vertex of the access graph.
type AzureGraphNode struct {
	Ref string `json:"ref"`
	// Kind is the identity's account kind (entra_user, entra_group, ...), or
	// resource, scope, workload or external.
	Kind        string                 `json:"kind"`
	Label       string                 `json:"label"`
	Sublabel    string                 `json:"sublabel,omitempty"`
	Sensitivity string                 `json:"sensitivity,omitempty"`
	Attrs       map[string]interface{} `json:"attrs,omitempty"`
}

// AzureGraphEdge is one directed edge: a grant, a membership, a federation
// trust or a workload running as an identity.
type AzureGraphEdge struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	From        string `json:"from"`
	To          string `json:"to"`
	Label       string `json:"label,omitempty"`
	Sensitivity string `json:"sensitivity,omitempty"`
	State       string `json:"state"`
	PathKind    string `json:"path_kind,omitempty"`
	Conclusion  string `json:"effective_conclusion,omitempty"`
}

// AzureGraphNeighbourhood is one node and everything one hop from it.
type AzureGraphNeighbourhood struct {
	Root  string           `json:"root"`
	Nodes []AzureGraphNode `json:"nodes"`
	Edges []AzureGraphEdge `json:"edges"`
	// Totals counts every live edge of each kind, so the client can say
	// "showing 40 of 445" when a cap applied.
	Totals    map[string]int `json:"totals"`
	Truncated bool           `json:"truncated"`
}

type nbBuilder struct {
	db    *gorm.DB
	ws    uuid.UUID
	out   *AzureGraphNeighbourhood
	nodes map[string]bool
}

func (b *nbBuilder) node(n AzureGraphNode) {
	if b.nodes[n.Ref] {
		return
	}
	b.nodes[n.Ref] = true
	b.out.Nodes = append(b.out.Nodes, n)
}

func (b *nbBuilder) edge(e AzureGraphEdge) { b.out.Edges = append(b.out.Edges, e) }

func (b *nbBuilder) total(kind string, n int) {
	b.out.Totals[kind] += n
	if n > azureGraphEdgeCap {
		b.out.Truncated = true
	}
}

// AzureNeighbourhoodOf reads one node's neighbourhood.
func AzureNeighbourhoodOf(db *gorm.DB, workspaceID uuid.UUID, ref string) (*AzureGraphNeighbourhood, error) {
	kind, id, ok := strings.Cut(ref, ":")
	if !ok || id == "" {
		return nil, fmt.Errorf("%w: %q is not <type>:<id>", ErrGraphNodeNotFound, ref)
	}
	b := &nbBuilder{db: db, ws: workspaceID, nodes: map[string]bool{},
		out: &AzureGraphNeighbourhood{Nodes: []AzureGraphNode{}, Edges: []AzureGraphEdge{}, Totals: map[string]int{}}}

	switch kind {
	case "object":
		var row struct{ ID uuid.UUID }
		if err := db.Raw(`SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND provider = ?
			AND lifecycle <> 'retired' AND provider_attrs->>'object_id' = lower(?) LIMIT 1`,
			workspaceID, models.ProviderAzure, id).Scan(&row).Error; err != nil {
			return nil, err
		}
		if row.ID == uuid.Nil {
			return nil, ErrGraphNodeNotFound
		}
		return b.identity(row.ID)
	case "native":
		// A resource by its Azure id (an ARM id, or an API permission's native
		// id), as the inventory lists it.
		var row struct{ ID uuid.UUID }
		if err := db.Raw(`SELECT id FROM iga_resources WHERE workspace_id = ? AND provider = ?
			AND lifecycle <> 'retired' AND provider_attrs->>'native_id' = lower(?) LIMIT 1`,
			workspaceID, models.ProviderAzure, id).Scan(&row).Error; err != nil {
			return nil, err
		}
		if row.ID == uuid.Nil {
			return nil, ErrGraphNodeNotFound
		}
		return b.resource(row.ID)
	case "identity", "resource", "workload", "external":
		uid, err := uuid.Parse(id)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrGraphNodeNotFound, err)
		}
		switch kind {
		case "identity":
			return b.identity(uid)
		case "resource":
			return b.resource(uid)
		case "workload":
			return b.workload(uid)
		}
		return b.external(uid)
	case "scope":
		return b.scope(id)
	}
	return nil, fmt.Errorf("%w: unknown node type %q", ErrGraphNodeNotFound, kind)
}

/* ---------------------------------- loaders ---------------------------------- */

type nbIdentity struct {
	ID          uuid.UUID
	DisplayName string
	AccountKind string
	Attrs       json.RawMessage `gorm:"column:provider_attrs"`
}

func (b *nbBuilder) identityNode(i nbIdentity) AzureGraphNode {
	attrs := map[string]interface{}{}
	_ = json.Unmarshal(i.Attrs, &attrs)
	keep := map[string]interface{}{}
	for _, k := range []string{"object_id", "user_principal_name", "app_id", "service_principal_type",
		"user_type", "enabled", "last_sign_in_at", "managed_identity_resource", "member_count",
		"agent_type", "agent_blueprint_name", "agent_blueprint_app_id", "agent_identity_name",
		"agent_user_principal_name", "agent_count"} {
		if v, ok := attrs[k]; ok && v != nil && v != "" {
			keep[k] = v
		}
	}
	sub, _ := attrs["user_principal_name"].(string)
	if sub == "" {
		sub, _ = attrs["app_id"].(string)
	}
	return AzureGraphNode{Ref: "identity:" + i.ID.String(), Kind: i.AccountKind, Label: i.DisplayName, Sublabel: sub, Attrs: keep}
}

func (b *nbBuilder) loadIdentities(ids []uuid.UUID) (map[uuid.UUID]nbIdentity, error) {
	out := map[uuid.UUID]nbIdentity{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []nbIdentity
	err := b.db.Raw(`SELECT id, display_name, account_kind, provider_attrs FROM iga_identity_accounts
		WHERE workspace_id = ? AND id IN ?`, b.ws, ids).Scan(&rows).Error
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, err
}

type nbGrant struct {
	ID           uuid.UUID
	SubjectID    uuid.UUID
	ResourceID   *uuid.UUID
	ResourceName string
	ResourceKind string
	NativeScope  string
	PathKind     string
	State        string
	Conclusion   string
	RoleName     string
	Action       string
	Sensitivity  string
}

const nbGrantSelect = `SELECT e.id, e.subject_identity_account_id AS subject_id, e.resource_id,
		COALESCE(r.display_name, '') AS resource_name, COALESCE(r.resource_kind, '') AS resource_kind,
		e.native_scope, e.path_kind, e.state, e.effective_conclusion AS conclusion,
		COALESCE(en.native_rights->>'role_name', '') AS role_name,
		COALESCE(en.native_rights->'actions'->>0, '') AS action,
		COALESCE(NULLIF(en.normalized_rights->>'sensitivity', ''), r.provider_attrs->>'sensitivity', 'low') AS sensitivity
	  FROM iga_access_edges e
	  LEFT JOIN iga_entitlements en ON en.id = e.entitlement_id
	  LEFT JOIN iga_resources r ON r.id = e.resource_id
	 WHERE e.workspace_id = ? AND e.provider = 'azure' AND e.state <> 'ended' AND `

const nbGrantOrder = ` ORDER BY CASE COALESCE(NULLIF(en.normalized_rights->>'sensitivity', ''), r.provider_attrs->>'sensitivity', 'low')
		WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END, e.path_kind, e.id LIMIT ?`

func (b *nbBuilder) grants(where string, args ...interface{}) ([]nbGrant, int, error) {
	var total int64
	countArgs := append([]interface{}{b.ws}, args...)
	if err := b.db.Raw(`SELECT count(*) FROM iga_access_edges e WHERE e.workspace_id = ? AND e.provider = 'azure'
		AND e.state <> 'ended' AND `+where, countArgs...).Scan(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []nbGrant
	err := b.db.Raw(nbGrantSelect+where+nbGrantOrder, append(countArgs, azureGraphEdgeCap)...).Scan(&rows).Error
	return rows, int(total), err
}

// grantTarget is the node a grant reaches: its resource, or the scope it was
// assigned at.
func grantTarget(g nbGrant) AzureGraphNode {
	if g.ResourceID != nil {
		return AzureGraphNode{Ref: "resource:" + g.ResourceID.String(), Kind: "resource",
			Label: g.ResourceName, Sublabel: g.ResourceKind, Sensitivity: g.Sensitivity}
	}
	return scopeNode(g.NativeScope)
}

// scopeNode names a grant's scope in words.
func scopeNode(scope string) AzureGraphNode {
	n := AzureGraphNode{Ref: "scope:" + scope, Kind: "scope", Label: scope}
	lower := strings.ToLower(scope)
	switch {
	case scope == "directory":
		n.Label, n.Sublabel = "Entra directory", "the whole tenant's directory"
	case scope == "/":
		n.Label, n.Sublabel = "Tenant root", "every subscription"
	case strings.Contains(lower, "/managementgroups/"):
		n.Label, n.Sublabel = "Management group "+lastSegment(scope), "every subscription below it"
	case strings.Contains(lower, "/resourcegroups/"):
		n.Label, n.Sublabel = "Resource group "+lastSegment(scope), scope
	case strings.HasPrefix(lower, "/subscriptions/"):
		n.Label, n.Sublabel = "Subscription "+lastSegment(scope), "the whole subscription"
	}
	return n
}

func lastSegment(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// grantLabel is what the edge says it grants.
func grantLabel(g nbGrant) string {
	switch g.PathKind {
	case "entra_app_permission":
		return "app permission"
	case "entra_delegated_permission":
		return "delegated permission"
	case "key_vault_access_policy":
		return "Key Vault policy"
	}
	if g.RoleName != "" {
		return g.RoleName
	}
	return g.Action
}

type nbRel struct {
	ID        uuid.UUID
	Type      string
	SourceID  *uuid.UUID
	Workload  *uuid.UUID
	External  *uuid.UUID
	TargetID  uuid.UUID
	State     string
	Mechanism string
}

func (b *nbBuilder) rels(where string, args ...interface{}) ([]nbRel, int, error) {
	all := append([]interface{}{b.ws, models.ProviderAzure + "\x1f%"}, args...)
	base := ` FROM iga_relationship WHERE workspace_id = ? AND source_key LIKE ? AND state <> 'ended' AND ` + where
	var total int64
	if err := b.db.Raw(`SELECT count(*)`+base, all...).Scan(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []nbRel
	err := b.db.Raw(`SELECT id, relationship_type AS type, source_identity_account_id AS source_id,
		source_workload_id AS workload, source_external_principal_id AS external,
		target_identity_account_id AS target_id, state, mechanism`+base+` ORDER BY id LIMIT ?`,
		append(all, azureGraphEdgeCap)...).Scan(&rows).Error
	return rows, int(total), err
}

/* ----------------------------------- roots ----------------------------------- */

func (b *nbBuilder) identity(id uuid.UUID) (*AzureGraphNeighbourhood, error) {
	self, err := b.loadIdentities([]uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	root, ok := self[id]
	if !ok {
		return nil, ErrGraphNodeNotFound
	}
	rootRef := "identity:" + id.String()
	b.out.Root = rootRef
	b.node(b.identityNode(root))

	grants, total, err := b.grants("e.subject_identity_account_id = ?", id)
	if err != nil {
		return nil, err
	}
	b.total("grant", total)
	for _, g := range grants {
		t := grantTarget(g)
		b.node(t)
		b.edge(AzureGraphEdge{ID: g.ID.String(), Kind: "grant", From: rootRef, To: t.Ref, Label: grantLabel(g),
			Sensitivity: g.Sensitivity, State: g.State, PathKind: g.PathKind, Conclusion: g.Conclusion})
	}

	// Relationships both ways: the groups it is in and, for a group, its
	// members; who can become it and whom it can become; what runs as it.
	// The root is one end of every relationship read here, so it is loaded
	// with the other ends.
	others := []uuid.UUID{id}
	var workloads, externals []uuid.UUID
	var relRows []nbRel
	for _, where := range []string{"source_identity_account_id = ?", "target_identity_account_id = ?"} {
		rows, _, err := b.rels(where, id)
		if err != nil {
			return nil, err
		}
		relRows = append(relRows, rows...)
	}
	for _, r := range relRows {
		if r.SourceID != nil && *r.SourceID != id {
			others = append(others, *r.SourceID)
		}
		if r.TargetID != id {
			others = append(others, r.TargetID)
		}
		if r.Workload != nil {
			workloads = append(workloads, *r.Workload)
		}
		if r.External != nil {
			externals = append(externals, *r.External)
		}
	}
	if err := b.addRelationships(relRows, others, workloads, externals); err != nil {
		return nil, err
	}
	return b.out, b.relTotals(id)
}

// relTotals counts every live relationship of the identity by type, beyond
// the capped rows drawn.
func (b *nbBuilder) relTotals(id uuid.UUID) error {
	var rows []struct {
		Type  string
		Count int
	}
	if err := b.db.Raw(`SELECT relationship_type AS type, count(*) AS count FROM iga_relationship
		WHERE workspace_id = ? AND source_key LIKE ? AND state <> 'ended'
		  AND (source_identity_account_id = ? OR target_identity_account_id = ?)
		GROUP BY 1`, b.ws, models.ProviderAzure+"\x1f%", id, id).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		b.total(r.Type, r.Count)
	}
	return nil
}

func (b *nbBuilder) addRelationships(rels []nbRel, identities, workloads, externals []uuid.UUID) error {
	ids, err := b.loadIdentities(identities)
	if err != nil {
		return err
	}
	wl := map[uuid.UUID]AzureGraphNode{}
	if len(workloads) > 0 {
		var rows []struct {
			ID          uuid.UUID
			DisplayName string
			RuntimeKind string
			Region      string
		}
		if err := b.db.Raw(`SELECT id, display_name, runtime_kind, region FROM iga_workload WHERE workspace_id = ? AND id IN ?`,
			b.ws, workloads).Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			wl[r.ID] = AzureGraphNode{Ref: "workload:" + r.ID.String(), Kind: "workload", Label: r.DisplayName,
				Sublabel: strings.TrimPrefix(r.RuntimeKind, "microsoft."), Attrs: map[string]interface{}{"region": r.Region}}
		}
	}
	ext := map[uuid.UUID]AzureGraphNode{}
	if len(externals) > 0 {
		var rows []struct {
			ID           uuid.UUID
			Issuer       string
			SubjectClaim string
			Mechanism    string
		}
		if err := b.db.Raw(`SELECT id, issuer, subject_claim, mechanism FROM iga_external_principal WHERE workspace_id = ? AND id IN ?`,
			b.ws, externals).Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			ext[r.ID] = AzureGraphNode{Ref: "external:" + r.ID.String(), Kind: "external", Label: r.SubjectClaim,
				Sublabel: r.Issuer, Attrs: map[string]interface{}{"mechanism": r.Mechanism}}
		}
	}
	for _, r := range rels {
		var from string
		switch {
		case r.SourceID != nil:
			n, ok := ids[*r.SourceID]
			if !ok {
				continue
			}
			b.node(b.identityNode(n))
			from = "identity:" + r.SourceID.String()
		case r.Workload != nil:
			n, ok := wl[*r.Workload]
			if !ok {
				continue
			}
			b.node(n)
			from = n.Ref
		case r.External != nil:
			n, ok := ext[*r.External]
			if !ok {
				continue
			}
			b.node(n)
			from = n.Ref
		}
		t, ok := ids[r.TargetID]
		if !ok {
			continue
		}
		b.node(b.identityNode(t))
		label := map[string]string{
			models.RelTypeMemberOf: "member of", models.RelTypeCanAssume: "can become", models.RelTypeExecutesAs: "runs as",
		}[r.Type]
		// How the source obtains the target's tokens, where it is not plain.
		switch r.Mechanism {
		case models.AssumeMechanismAgentBlueprint:
			label = "acts as agent (blueprint)"
		case models.AssumeMechanismAgentUser:
			label = "acts as its agent user"
		case models.AssumeMechanismEntraOwner:
			label = "owner (can add a credential)"
		case models.AssumeMechanismEntraAppRegistration:
			label = "its service principal"
		}
		b.edge(AzureGraphEdge{ID: r.ID.String(), Kind: r.Type, From: from, To: "identity:" + r.TargetID.String(),
			Label: label, State: r.State})
	}
	return nil
}

// holders adds the identities holding the given grants, pointing at target.
func (b *nbBuilder) holders(grants []nbGrant, target string) error {
	ids := make([]uuid.UUID, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.SubjectID)
	}
	loaded, err := b.loadIdentities(ids)
	if err != nil {
		return err
	}
	for _, g := range grants {
		n, ok := loaded[g.SubjectID]
		if !ok {
			continue
		}
		b.node(b.identityNode(n))
		b.edge(AzureGraphEdge{ID: g.ID.String(), Kind: "grant", From: "identity:" + g.SubjectID.String(), To: target,
			Label: grantLabel(g), Sensitivity: g.Sensitivity, State: g.State, PathKind: g.PathKind, Conclusion: g.Conclusion})
	}
	return nil
}

func (b *nbBuilder) resource(id uuid.UUID) (*AzureGraphNeighbourhood, error) {
	var r struct {
		ID           uuid.UUID
		DisplayName  string
		ResourceKind string
		Attrs        json.RawMessage `gorm:"column:provider_attrs"`
	}
	if err := b.db.Raw(`SELECT id, display_name, resource_kind, provider_attrs FROM iga_resources
		WHERE workspace_id = ? AND id = ? AND provider = ?`, b.ws, id, models.ProviderAzure).Scan(&r).Error; err != nil {
		return nil, err
	}
	if r.ID == uuid.Nil {
		return nil, ErrGraphNodeNotFound
	}
	attrs := map[string]interface{}{}
	_ = json.Unmarshal(r.Attrs, &attrs)
	sens, _ := attrs["sensitivity"].(string)
	ref := "resource:" + id.String()
	b.out.Root = ref
	b.node(AzureGraphNode{Ref: ref, Kind: "resource", Label: r.DisplayName, Sublabel: r.ResourceKind,
		Sensitivity: sens, Attrs: attrs})
	grants, total, err := b.grants("e.resource_id = ?", id)
	if err != nil {
		return nil, err
	}
	b.total("grant", total)
	return b.out, b.holders(grants, ref)
}

func (b *nbBuilder) scope(scope string) (*AzureGraphNeighbourhood, error) {
	n := scopeNode(scope)
	b.out.Root = n.Ref
	b.node(n)
	grants, total, err := b.grants("e.resource_id IS NULL AND e.native_scope = ?", scope)
	if err != nil {
		return nil, err
	}
	if total == 0 {
		return nil, ErrGraphNodeNotFound
	}
	b.total("grant", total)
	return b.out, b.holders(grants, n.Ref)
}

func (b *nbBuilder) workload(id uuid.UUID) (*AzureGraphNeighbourhood, error) {
	rels, n, err := b.rels("source_workload_id = ?", id)
	if err != nil {
		return nil, err
	}
	var w struct {
		ID          uuid.UUID
		DisplayName string
		RuntimeKind string
		Region      string
	}
	if err := b.db.Raw(`SELECT id, display_name, runtime_kind, region FROM iga_workload WHERE workspace_id = ? AND id = ? AND provider = ?`,
		b.ws, id, models.ProviderAzure).Scan(&w).Error; err != nil {
		return nil, err
	}
	if w.ID == uuid.Nil {
		return nil, ErrGraphNodeNotFound
	}
	b.out.Root = "workload:" + id.String()
	b.node(AzureGraphNode{Ref: b.out.Root, Kind: "workload", Label: w.DisplayName,
		Sublabel: strings.TrimPrefix(w.RuntimeKind, "microsoft."), Attrs: map[string]interface{}{"region": w.Region}})
	b.total(models.RelTypeExecutesAs, n)
	var targets []uuid.UUID
	for _, r := range rels {
		targets = append(targets, r.TargetID)
	}
	return b.out, b.addRelationships(rels, targets, []uuid.UUID{id}, nil)
}

func (b *nbBuilder) external(id uuid.UUID) (*AzureGraphNeighbourhood, error) {
	rels, n, err := b.rels("source_external_principal_id = ?", id)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrGraphNodeNotFound
	}
	b.out.Root = "external:" + id.String()
	b.total(models.RelTypeCanAssume, n)
	var targets []uuid.UUID
	for _, r := range rels {
		targets = append(targets, r.TargetID)
	}
	return b.out, b.addRelationships(rels, targets, nil, []uuid.UUID{id})
}
