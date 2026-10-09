package igaread

// GET /api/iga/v1/identities/:id (§5.3 Identities, T6.3): the identity list
// row -- built by the SAME IdentityRecord.Row the list uses, so a row and the
// object it opens never disagree (§2.14.11) -- plus continuity,
// immutable_key, the D-85 provider_attrs allowlist, a user's access keys and
// the sources that hold it. Retired identities are readable (§5.2): the row
// is read from its own columns and its support rows in any state.

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// IdentityDetail is the /identities/:id data object.
//
// retired_reason is always present here (null while active), as on every
// detail route: the list row omits it on active rows, and a detail must say
// why a retired object is retired (§5.2 "Retired objects"; D-98).
type IdentityDetail struct {
	IdentityRow
	RetiredReason *string        `json:"retired_reason"`
	FirstSeenAt   any            `json:"first_seen_at"`
	Continuity    string         `json:"continuity"`
	ImmutableKey  string         `json:"immutable_key"`
	ProviderAttrs map[string]any `json:"provider_attrs"`
	// Credentials is present for users only: a role or group holds no access
	// keys, and an absent list claims nothing about them.
	Credentials *[]IdentityCredential `json:"credentials,omitempty"`
	Sources     []SupportSource       `json:"sources"`
}

// IdentityCredential is one access key of a user (§5.3, §1.4 iam_access_keys;
// D-86). Non-secret metadata only: no value is ever stored or returned.
//
// status is AWS's own Active/Inactive, mapped from the stored lifecycle,
// which is the only place the projector records it (project.go
// projectCredentials writes lifecycle 'revoked' for a key AWS reports
// Inactive, and 'active' otherwise):
//
//	lifecycle active   -> status "Active"
//	lifecycle revoked  -> status "Inactive"
//	anything else      -> status null (expired and rotated are not AWS
//	                      statuses; nothing stored says what AWS reported)
//
// lifecycle is returned beside it, unmapped (D-86). created_at is the stored
// issued_at, null while the projector does not record it. last_seen_at is when
// a scan last reported the key. A key deleted in AWS is revoked once an
// authoritative read of its user no longer lists it (§2.5,
// Reconciler.reconcileCredentials); until such a read, an old last_seen_at is
// the honest signal that it may be gone.
type IdentityCredential struct {
	KeyID      string  `json:"key_id"`
	Status     *string `json:"status"`
	Lifecycle  string  `json:"lifecycle"`
	CreatedAt  any     `json:"created_at"`
	LastUsedAt any     `json:"last_used_at"`
	LastSeenAt any     `json:"last_seen_at"`
}

// Credential statuses exactly as AWS names them (iam:ListAccessKeys
// StatusType), as D-86 has the API return them -- not the lower-cased
// cloud_secret status the collector stores.
const (
	CredentialStatusActive   = "Active"
	CredentialStatusInactive = "Inactive"
)

// credentialLifecycleRevoked is the lifecycle projectCredentials writes for a
// key AWS reports Inactive (a provider fact, not an inference from absence).
const credentialLifecycleRevoked = "revoked"

// CredentialStatusOf maps a stored credential lifecycle to AWS's status (see
// IdentityCredential): nil when the lifecycle does not record one.
func CredentialStatusOf(lifecycle string) *string {
	var s string
	switch lifecycle {
	case models.LifecycleActive:
		s = CredentialStatusActive
	case credentialLifecycleRevoked:
		s = CredentialStatusInactive
	default:
		return nil
	}
	return &s
}

// GetIdentity serves GET /identities/:id. 404 not_found -- with no hint --
// when nothing is published yet (D-4), when the id is malformed or another
// type's reference (D-5), and when it is not a readable identity of this
// workspace (D-6: a GitHub row, or an AWS row no pass supported).
func (r *Reader) GetIdentity(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	rev, perr := idetailParams(vals, "rev")
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefIdentity, rawID)
	if nerr != nil {
		return nil, nerr
	}
	var out Envelope
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		ident, err := idetailLoadIdentity(q, id)
		if err != nil {
			return err
		}
		if ident == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}

		// used_by_count: the list's own count, OPTIONAL (§5.1) -- a count
		// that does not finish is {value: null, exact: false}, never a number
		// that looks exact.
		used := Unknown()
		var counts map[uuid.UUID]Exact
		ok, err := q.Optional(func(tx *gorm.DB) error {
			var err error
			counts, err = UsedByCounts(tx, q.WS, []uuid.UUID{id})
			return err
		})
		if err != nil {
			return err
		}
		if c, has := counts[id]; ok && has {
			used = c
		}
		var stale *[]StaleReason
		if ident.State == StateStale {
			reasons, err := NodeStaleReasons(q, accts, "identity_account_id", []StaleSubject{ident.StaleSubject()})
			if err != nil {
				return err
			}
			stale = StaleReasonOf(ident.State, id, reasons)
		}
		sources, err := SupportSources(q, accts, "identity_account_id", id)
		if err != nil {
			return err
		}
		detail := IdentityDetail{
			IdentityRow:   ident.Row(accts, used, stale),
			RetiredReason: strPtr(ident.RetiredReason),
			FirstSeenAt:   T(ident.FirstSeenAt),
			Continuity:    ident.Continuity,
			ImmutableKey:  ident.ImmutableKey,
			ProviderAttrs: IdentityProviderAttrs(ident.AccountKind, ident.ProviderAttrs),
			Sources:       sources,
		}
		if ident.AccountKind == models.CloudIdentityIAMUser {
			creds, err := idetailCredentials(q, id)
			if err != nil {
				return err
			}
			detail.Credentials = &creds
		}
		meta := IdentityTabMeta{DetailMeta: NewDetailMeta(q)}
		if meta.Coverage, err = idetailCoverage(q, accts, idetailSupportPairs, []any{q.WS, id},
			idetailDetailSurfaces(ident.AccountKind)); err != nil {
			return err
		}
		out = Envelope{Data: detail, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// idetailDetailSurfaces is what bears on an identity's Overview: its own
// listing (roles, users or groups), and for a user the access-key listing,
// without which an empty credentials list would read as "no keys".
func idetailDetailSurfaces(kind string) idetailSurfaces {
	w := idetailSurfaces{exact: map[string]string{}, revoked: "this identity is no longer refreshed"}
	switch kind {
	case models.CloudIdentityIAMRole:
		w.exact[models.SurfaceIAMRoles] = "this role's attributes and trust document"
	case models.CloudIdentityIAMUser:
		w.exact[models.SurfaceIAMUsers] = "this user's attributes"
		w.exact[models.SurfaceIAMAccessKeys] = "this user's access keys"
	case models.CloudIdentityIAMGroup:
		w.exact[models.SurfaceIAMGroups] = "this group's attributes"
	}
	return w
}

// IdentityProviderAttrs renders an identity's provider_attrs through D-85's
// allowlist -- never the raw jsonb: path, tags, permissions_boundary_arn,
// trust_has_deny and trust_has_not_principal (D-44), on EVERY kind, so the
// object has one shape whatever the identity is (§5.3 lists the five for
// identity detail without qualification; D-98, D-102d).
//
// A trust flag is stated only for a role, and only as the projector wrote it:
// null means "not stated", never false. A recreated role whose document could
// not be read carries none (trustFlags), and false would claim its trust has
// no Deny. A user or group has no trust document at all, so its flags are
// null too -- present, like a group's permissions_boundary_arn, never a false
// no trust document was read to support, and never absent (a missing key
// would make the console infer from the kind). permissions_boundary_arn is
// null when none is recorded; tags are {} when none are.
func IdentityProviderAttrs(kind string, raw json.RawMessage) map[string]any {
	var in map[string]any
	_ = json.Unmarshal(raw, &in)
	out := map[string]any{"path": nil, "tags": map[string]any{}, "permissions_boundary_arn": nil,
		igagraph.TrustHasDenyAttr: nil, igagraph.TrustHasNotPrincipalAttr: nil}
	if p, ok := in["path"].(string); ok {
		out["path"] = p
	}
	if t, ok := in["tags"].(map[string]any); ok {
		out["tags"] = t
	}
	if b, ok := in["permissions_boundary_arn"].(string); ok && b != "" {
		out["permissions_boundary_arn"] = b
	}
	if kind == models.CloudIdentityIAMRole {
		for _, k := range []string{igagraph.TrustHasDenyAttr, igagraph.TrustHasNotPrincipalAttr} {
			if v, ok := in[k].(bool); ok {
				out[k] = v
			}
		}
	}
	return out
}

// idetailCredentials reads a user's access keys, newest first.
//
// ONE entry per key. The projector's upsert once conflicted only with a live
// (non-revoked) row (028's partial uq_iga_credentials_source_key), so a key
// that turned Inactive was INSERTED again as 'revoked' on every pass while its
// original row stayed 'active' with a frozen last_seen_at. D-64 fixed the
// projector (UpsertCredential now updates the key's one row in place); rows a
// build before that fix wrote may still hold duplicates, so the latest reading
// still wins here: per source key, the row a scan wrote most recently
// (last_seen_at, then updated_at, then id). Showing every row would list one
// key twice, once as active -- a claim no current scan makes.
func idetailCredentials(q *Query, id uuid.UUID) ([]IdentityCredential, error) {
	var rows []struct {
		KeyIdentifier string
		Lifecycle     string
		IssuedAt      *time.Time
		LastUsedAt    *time.Time
		FirstSeenAt   time.Time
		LastSeenAt    time.Time
	}
	if err := q.DB().Raw(`SELECT key_identifier, lifecycle, issued_at, last_used_at, first_seen_at, last_seen_at
	                        FROM (SELECT DISTINCT ON (c.source_key) c.*
	                                FROM iga_credentials c
	                               WHERE c.workspace_id = ? AND c.identity_account_id = ? AND c.provider = 'aws'
	                               ORDER BY c.source_key, c.last_seen_at DESC, c.updated_at DESC, c.id DESC) latest`,
		q.WS, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i].FirstSeenAt, rows[j].FirstSeenAt
		if rows[i].IssuedAt != nil {
			a = *rows[i].IssuedAt
		}
		if rows[j].IssuedAt != nil {
			b = *rows[j].IssuedAt
		}
		if !a.Equal(b) {
			return a.After(b)
		}
		return rows[i].KeyIdentifier < rows[j].KeyIdentifier
	})
	out := make([]IdentityCredential, 0, len(rows))
	for _, c := range rows {
		out = append(out, IdentityCredential{
			KeyID:      c.KeyIdentifier,
			Status:     CredentialStatusOf(c.Lifecycle),
			Lifecycle:  c.Lifecycle,
			CreatedAt:  TS(c.IssuedAt),
			LastUsedAt: TS(c.LastUsedAt),
			LastSeenAt: T(c.LastSeenAt),
		})
	}
	return out, nil
}
