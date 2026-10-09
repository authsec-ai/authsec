package igaread

// GET /api/iga/v1/lookup?cloud_ref=cloud_identity:<id>|cloud_workload:<id>
// (§5.3 Lookup, T6.8, D-81): the graph object projected from a Cloud
// Inventory row, behind Cloud Inventory's "Open in graph" (§2.14.5).
//
// The object is found the way the projector made it -- the row's source key,
// rebuilt with igagraph's own key functions, through the row's OWN connector
// -- and NEVER by name: names repeat across accounts, so a name match would
// open the other account's role.

import (
	"context"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// Cloud Inventory row references /lookup accepts. They name cloud_* rows, not
// graph objects, so they are not graph reference types (refs.go) and no other
// route accepts them.
const (
	RefCloudIdentity = "cloud_identity"
	RefCloudWorkload = "cloud_workload"
)

// LookupResult is /lookup's data: the graph object's typed reference and its
// lifecycle.
type LookupResult struct {
	Ref       string `json:"ref"`
	Lifecycle string `json:"lifecycle"`
}

// Lookup serves GET /lookup. It is revision-bound like every graph read: it
// echoes meta.rev and a stale rev parameter is 409 (D-82). 404 not_found when
// the row is not this workspace's, is not AWS, or has no projected counterpart
// supported by its connector -- and when nothing is published yet (D-4: no
// object exists before the first publication).
func (r *Reader) Lookup(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	for name := range vals {
		if name != "cloud_ref" && name != "rev" {
			return nil, InvalidParameter(name, name+" is not a parameter of /lookup")
		}
	}
	typ, id, perr := parseCloudRef(vals.Get("cloud_ref"))
	if perr != nil {
		return nil, perr
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}

	var out Envelope
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		var res *LookupResult
		var err error
		switch typ {
		case RefCloudIdentity:
			res, err = lookupIdentity(q, id)
		default:
			res, err = lookupWorkload(q, id)
		}
		if err != nil {
			return err
		}
		if res == nil {
			return NotFound()
		}
		out = Envelope{Data: res, Meta: NewDetailMeta(q)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// parseCloudRef reads cloud_ref: a missing, malformed or other-typed value is
// 400 invalid_parameter (it is a malformed parameter, not an absent object).
func parseCloudRef(raw string) (string, uuid.UUID, *Error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", uuid.Nil, InvalidParameter("cloud_ref", "cloud_ref is required")
	}
	typ, rest, ok := strings.Cut(raw, ":")
	if !ok || (typ != RefCloudIdentity && typ != RefCloudWorkload) {
		return "", uuid.Nil, InvalidParameter("cloud_ref", "cloud_ref must be cloud_identity:<id> or cloud_workload:<id>")
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return "", uuid.Nil, InvalidParameter("cloud_ref", "cloud_ref has a malformed id")
	}
	return typ, id, nil
}

// lookupConnector returns the account an AWS connector of this workspace
// reads, or ok=false (another provider's rows are never projected).
//
// It also returns the connector's AWS partition (attrs.partition; "" is aws):
// a workload's key is its ARN, CONSTRUCTED in that partition when the row holds
// a bare id, so /lookup must build it exactly as the projector does
// (igagraph.WorkloadKey, T3.6).
func lookupConnector(q *Query, connectorID uuid.UUID) (account, partition string, ok bool, err error) {
	var rows []struct {
		Provider  string
		ScopeID   string
		Partition string
	}
	if err := q.DB().Raw(`SELECT provider, scope_id, COALESCE(attrs->>'partition', '') AS partition
	                        FROM cloud_connector WHERE workspace_id = ? AND id = ?`,
		q.WS, connectorID).Scan(&rows).Error; err != nil {
		return "", "", false, err
	}
	if len(rows) == 0 || rows[0].Provider != models.ProviderAWS {
		return "", "", false, nil
	}
	return rows[0].ScopeID, rows[0].Partition, true, nil
}

// lookupOrder prefers the active object, else the most recently seen retired
// incarnation (D-81): detail routes serve retired objects (§5.2), so a Cloud
// Inventory row whose object has since been retired still opens it.
const lookupOrder = `ORDER BY (n.lifecycle = 'active') DESC, n.last_seen_at DESC, n.id LIMIT 1`

// lookupIdentity: cloud_identity -> iga_identity_accounts.
//
// The key is igagraph.IdentityKey, the projector's own. A match must carry
// the row's immutable key when the row has one: a role deleted and recreated
// under the same ARN has the SAME key and a DIFFERENT RoleId, and until the
// recreation is projected the live node is the OLD principal -- opening it
// from the new row would show another principal's history as this one's
// (§2.4). So no node with the row's RoleId is 404, never the old node. And it
// must be supported by the row's own connector (a support row in any state:
// a retired object's supports have ended).
func lookupIdentity(q *Query, id uuid.UUID) (*LookupResult, error) {
	var rows []models.CloudIdentity
	if err := q.DB().Where("workspace_id = ? AND id = ?", q.WS, id).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	ci := rows[0]
	if _, _, ok, err := lookupConnector(q, ci.ConnectorID); err != nil || !ok {
		return nil, err
	}
	imm := igagraph.ImmutableKey(ci)
	var nodes []LookupResult
	if err := q.DB().Raw(`SELECT 'identity:' || n.id AS ref, n.lifecycle
	                        FROM iga_identity_accounts n
	                       WHERE n.workspace_id = ? AND n.provider = 'aws' AND n.source_key = ?
	                         AND (? = '' OR n.immutable_key = ?)
	                         AND EXISTS (SELECT 1 FROM iga_object_support s
	                                      WHERE s.workspace_id = n.workspace_id AND s.identity_account_id = n.id
	                                        AND s.connector_id = ?)
	                       `+lookupOrder,
		q.WS, igagraph.IdentityKey(ci), imm, imm, ci.ConnectorID).Scan(&nodes).Error; err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	return &nodes[0], nil
}

// lookupWorkload: cloud_workload -> iga_workload, keyed by igagraph.WorkloadKey
// with the row's connector's account -- the same construction the projector
// uses for EC2 instances and bare Bedrock ids -- and supported by that
// connector. A Cloud Inventory workload row carries no creation-boundary id,
// so the key is the whole match.
func lookupWorkload(q *Query, id uuid.UUID) (*LookupResult, error) {
	var rows []models.CloudWorkload
	if err := q.DB().Where("workspace_id = ? AND id = ?", q.WS, id).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	cw := rows[0]
	account, partition, ok, err := lookupConnector(q, cw.ConnectorID)
	if err != nil || !ok {
		return nil, err
	}
	var nodes []LookupResult
	if err := q.DB().Raw(`SELECT 'workload:' || n.id AS ref, n.lifecycle
	                        FROM iga_workload n
	                       WHERE n.workspace_id = ? AND n.provider = 'aws' AND n.source_key = ?
	                         AND EXISTS (SELECT 1 FROM iga_object_support s
	                                      WHERE s.workspace_id = n.workspace_id AND s.workload_id = n.id
	                                        AND s.connector_id = ?)
	                       `+lookupOrder,
		q.WS, igagraph.WorkloadKey(cw, partition, account), cw.ConnectorID).Scan(&nodes).Error; err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	return &nodes[0], nil
}
