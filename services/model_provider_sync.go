package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/modelprovider"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

/* model_provider_sync.go is the hourly sync of a connected model provider
   organisation (SPEC-agent-runtime-provider-usage.md §5, §8):

     1. claim the connection under RLS (a lease, safe on every replica);
     2. read the admin key from Vault and call the provider OUTSIDE any
        transaction: keys, hourly usage since the high-water mark (2 h overlap,
        30 days the first time), OpenAI key audit events;
     3. in ONE tenancy.InWorkspace transaction: upsert keys (absent ones become
        deleted), upsert usage buckets (provider totals replace the stored
        ones), purge usage past retention, recompute the weak links and the
        unaccounted_model_usage findings, schedule the next sync.

   No prompt, completion or key value is read or stored. */

// FindingUnaccountedModelUsage: a provider key used models in the last 7 days
// and nothing in the workspace's AWS accounts names it (weak attribution).
const FindingUnaccountedModelUsage = "unaccounted_model_usage"

// Windows of the finding (spec §5).
const (
	unaccountedWindow  = 7 * 24 * time.Hour
	unaccountedResolve = 30 * 24 * time.Hour
)

func init() {
	// The findings list filter admits the kind (agent_runtime_findings.go).
	FindingKinds[FindingUnaccountedModelUsage] = true
}

func unaccountedSubjectPrefix(connection uuid.UUID) string {
	return "model_provider:" + connection.String() + ":"
}

/* ---------------------------------- the worker ------------------------------ */

// RunModelProviderSyncWorker syncs due connections every minute until ctx
// ends. AUTHSEC_DISABLE_MODEL_PROVIDER_SYNC=true turns it off.
func RunModelProviderSyncWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_MODEL_PROVIDER_SYNC") == "true" {
		log.Printf("[model-providers] sync worker not started: AUTHSEC_DISABLE_MODEL_PROVIDER_SYNC=true")
		return
	}
	s := NewModelProviderService(db)
	for {
		if _, err := s.SyncDue(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[model-providers] sync: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// SyncDue syncs up to 10 due connections, each in its own workspace. It
// returns how many synced.
func (s *ModelProviderService) SyncDue(ctx context.Context) (int, error) {
	var due []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	now := s.now().UTC()
	// TENANT-EXEMPT: the model provider sync worker runs across workspaces (no request tenant) and lists due connection ids only; each is claimed, synced and recorded in its own workspace_id-bound transaction (tenancy.InWorkspace).
	if err := s.db.WithContext(ctx).Raw(`SELECT workspace_id, id FROM model_provider_connection
	                                      WHERE status <> 'revoked' AND next_sync_at IS NOT NULL AND next_sync_at <= ?
	                                        AND (sync_lease_until IS NULL OR sync_lease_until < ?)
	                                      ORDER BY next_sync_at LIMIT 10`, now, now).Scan(&due).Error; err != nil {
		return 0, err
	}
	n := 0
	var first error
	for _, d := range due {
		_, err := s.SyncConnection(ctx, d.WorkspaceID, d.ID)
		switch {
		case err == nil:
			n++
		case errors.Is(err, errModelProviderNotClaimed):
		default:
			log.Printf("[model-providers] workspace %s connection %s: %v", d.WorkspaceID, d.ID, err)
			if first == nil {
				first = err
			}
		}
	}
	return n, first
}

var errModelProviderNotClaimed = errors.New("model provider connection not claimable (revoked, gone or leased)")

// ModelProviderSyncResult reports one sync.
type ModelProviderSyncResult struct {
	Keys             int
	KeysTruncated    bool
	UsageRows        int
	From, To         time.Time
	AuditEvents      int
	AuditUnavailable bool
	FindingsOpen     int
	FindingsResolved int
	KeysLinked       int
}

type modelProviderClaim struct {
	Provider    string
	SecretRef   string
	UsageCursor *time.Time
	DisplayName string
}

// SyncConnection syncs one connection now (the worker, and tests).
func (s *ModelProviderService) SyncConnection(ctx context.Context, ws, id uuid.UUID) (*ModelProviderSyncResult, error) {
	now := s.now().UTC()
	var claims []modelProviderClaim
	if err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`UPDATE model_provider_connection
			SET sync_lease_until = ?, last_sync_attempt_at = ?, updated_at = ?
			WHERE workspace_id = ? AND id = ? AND status <> 'revoked'
			  AND (sync_lease_until IS NULL OR sync_lease_until < ?)
			RETURNING provider, secret_ref, usage_cursor, display_name`,
			now.Add(modelProviderLease), now, now, ws, id, now).Scan(&claims).Error
	}); err != nil {
		return nil, err
	}
	if len(claims) != 1 {
		return nil, errModelProviderNotClaimed
	}
	cl := claims[0]
	res := &ModelProviderSyncResult{}
	fetched, err := s.fetch(ctx, cl, now, res)
	if err != nil {
		if rerr := s.recordFailure(ctx, ws, id, err, now); rerr != nil {
			log.Printf("[model-providers] workspace %s connection %s: recording a failed sync: %v", ws, id, rerr)
		}
		return res, err
	}
	if err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return s.apply(tx, ws, id, cl, fetched, now, res)
	}); err != nil {
		if rerr := s.recordFailure(ctx, ws, id, err, now); rerr != nil {
			log.Printf("[model-providers] workspace %s connection %s: recording a failed sync: %v", ws, id, rerr)
		}
		return res, err
	}
	return res, nil
}

type modelProviderFetched struct {
	keys      []modelprovider.Key
	truncated bool
	usage     []modelprovider.UsageRow
	events    []modelprovider.KeyEvent
	from, to  time.Time
}

// errModelProviderSecret is a key that could not be read from Vault.
type errModelProviderSecret struct{ msg string }

func (e errModelProviderSecret) Error() string { return e.msg }

// fetch reads the key from Vault and the provider. Never in a transaction.
func (s *ModelProviderService) fetch(ctx context.Context, cl modelProviderClaim, now time.Time, res *ModelProviderSyncResult) (*modelProviderFetched, error) {
	vc := modelProviderVault()
	if vc == nil {
		return nil, errModelProviderSecret{"the secrets store is not configured"}
	}
	sec, err := vc.ReadSecret(cl.SecretRef)
	if err != nil {
		return nil, errModelProviderSecret{"the admin key could not be read from the secrets store"}
	}
	key, _ := sec["admin_key"].(string)
	if key == "" {
		return nil, errModelProviderSecret{"the stored admin key is empty"}
	}
	client, err := s.newClient(cl.Provider, key)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, modelProviderCallTimeout)
	defer cancel()

	out := &modelProviderFetched{to: now}
	out.from = now.Add(-modelProviderFirstWindow).Truncate(time.Hour)
	if cl.UsageCursor != nil {
		if f := cl.UsageCursor.UTC().Add(-modelProviderOverlap).Truncate(time.Hour); f.After(out.from) {
			out.from = f
		}
	}
	res.From, res.To = out.from, out.to
	if out.keys, out.truncated, err = client.ListKeys(cctx, modelProviderMaxKeys); err != nil {
		return nil, err
	}
	if out.usage, err = client.Usage(cctx, out.from, out.to); err != nil {
		return nil, err
	}
	// Audit logs are optional: an organisation that has not enabled them
	// answers with an error (possibly 403), which is "no events", never a
	// failed sync or a refused key -- the listing above already proved it.
	if evs, err := client.KeyEvents(cctx, out.from); err == nil {
		out.events = evs
	} else {
		res.AuditUnavailable = true
	}
	res.Keys, res.KeysTruncated, res.UsageRows, res.AuditEvents = len(out.keys), out.truncated, len(out.usage), len(out.events)
	return out, nil
}

// recordFailure: a refused key stops automatic syncs (status error) until a
// rotation or a manual sync; anything else retries at the next hour.
func (s *ModelProviderService) recordFailure(ctx context.Context, ws, id uuid.UUID, cause error, now time.Time) error {
	msg := modelprovider.Scrub(cause.Error())
	status := "status"
	next := any(now.Add(modelProviderSyncEvery))
	if modelprovider.IsAuth(cause) {
		status = "'error'"
		next = nil
		msg = "The provider refused the admin key: " + msg + " Rotate the key, then sync."
	}
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Exec(`UPDATE model_provider_connection
			SET status = `+status+`, last_error = ?, next_sync_at = ?, sync_lease_until = NULL, updated_at = ?
			WHERE workspace_id = ? AND id = ? AND status <> 'revoked'`, truncate(msg, 500), next, now, ws, id).Error
	})
}

/* ------------------------------------ apply --------------------------------- */

func (s *ModelProviderService) apply(tx *gorm.DB, ws, id uuid.UUID, cl modelProviderClaim, f *modelProviderFetched,
	now time.Time, res *ModelProviderSyncResult) error {
	// The connection may have been revoked while the provider was read.
	var st []string
	if err := tx.Raw(`SELECT status FROM model_provider_connection WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).Scan(&st).Error; err != nil {
		return err
	}
	if len(st) != 1 || st[0] == ModelProviderRevoked {
		return errModelProviderNotClaimed
	}

	deleted := map[string]bool{}
	for _, e := range f.events {
		if e.Type == "api_key.deleted" {
			deleted[e.KeyID] = true
		}
	}
	listed := map[string]bool{}
	for _, k := range f.keys {
		listed[k.ID] = true
		if err := tx.Exec(`INSERT INTO model_provider_key
			  (workspace_id, connection_id, provider_key_id, name, key_hint, project_id, project_name, owner_type, owner_id,
			   owner_name, created_at_provider, last_used_at, status, first_seen, last_seen, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (workspace_id, connection_id, provider_key_id) DO UPDATE SET
			  name = excluded.name, key_hint = excluded.key_hint, project_id = excluded.project_id,
			  project_name = excluded.project_name, owner_type = excluded.owner_type, owner_id = excluded.owner_id,
			  owner_name = excluded.owner_name, created_at_provider = excluded.created_at_provider,
			  last_used_at = GREATEST(model_provider_key.last_used_at, excluded.last_used_at),
			  status = excluded.status, last_seen = excluded.last_seen, updated_at = excluded.updated_at`,
			ws, id, truncate(k.ID, 200), truncate(k.Name, 300), truncate(k.Hint, 100), truncate(k.ProjectID, 200),
			truncate(k.ProjectName, 300), k.OwnerType, truncate(k.OwnerID, 200), truncate(k.OwnerName, 300),
			k.CreatedAt, k.LastUsedAt, k.Status, now, now, now).Error; err != nil {
			return fmt.Errorf("upsert key: %w", err)
		}
	}
	// A key no longer listed is deleted (only when the listing was complete).
	if !f.truncated {
		var known []string
		if err := tx.Raw(`SELECT provider_key_id FROM model_provider_key
		                   WHERE workspace_id = ? AND connection_id = ? AND status <> 'deleted'`, ws, id).Scan(&known).Error; err != nil {
			return err
		}
		var gone []string
		for _, k := range known {
			if !listed[k] {
				gone = append(gone, k)
			}
		}
		if len(gone) > 0 {
			if err := tx.Exec(`UPDATE model_provider_key SET status = 'deleted', updated_at = ?
			                    WHERE workspace_id = ? AND connection_id = ? AND provider_key_id IN ?`, now, ws, id, gone).Error; err != nil {
				return err
			}
		}
	}
	// A key seen in usage but never listed: deleted (audit log) or unknown.
	usedOnly := map[string]string{}
	for _, u := range f.usage {
		if u.KeyID != "" && !listed[u.KeyID] {
			usedOnly[u.KeyID] = u.ProjectID
		}
	}
	for keyID, project := range usedOnly {
		status := "unknown"
		if deleted[keyID] {
			status = "deleted"
		}
		if err := tx.Exec(`INSERT INTO model_provider_key
			  (workspace_id, connection_id, provider_key_id, project_id, status, first_seen, last_seen, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (workspace_id, connection_id, provider_key_id) DO UPDATE SET
			  status = CASE WHEN model_provider_key.status = 'deleted' THEN 'deleted' ELSE excluded.status END,
			  updated_at = excluded.updated_at`,
			ws, id, truncate(keyID, 200), truncate(project, 200), status, now, now, now).Error; err != nil {
			return fmt.Errorf("record unlisted key: %w", err)
		}
	}

	if err := upsertModelProviderUsage(tx, ws, id, f.usage, now); err != nil {
		return err
	}
	// Last used: the newest hour with usage, when newer than the provider's.
	if err := tx.Exec(`UPDATE model_provider_key k SET last_used_at = u.last
		  FROM (SELECT provider_key_id, max(bucket_start) AS last FROM model_provider_usage
		         WHERE workspace_id = ? AND connection_id = ? AND provider_key_id <> '' GROUP BY provider_key_id) u
		 WHERE k.workspace_id = ? AND k.connection_id = ? AND k.provider_key_id = u.provider_key_id
		   AND (k.last_used_at IS NULL OR k.last_used_at < u.last)`, ws, id, ws, id).Error; err != nil {
		return fmt.Errorf("last used: %w", err)
	}
	if err := tx.Exec(`DELETE FROM model_provider_usage WHERE workspace_id = ? AND connection_id = ? AND bucket_start < ?`,
		ws, id, now.Add(-modelProviderRetention)).Error; err != nil {
		return fmt.Errorf("retention: %w", err)
	}

	if err := s.applyAttribution(tx, ws, id, cl, now, res); err != nil {
		return err
	}

	lastErr := ""
	if f.truncated {
		lastErr = fmt.Sprintf("Only the first %d keys of the organisation are stored.", modelProviderMaxKeys)
	}
	return tx.Exec(`UPDATE model_provider_connection
		SET status = 'active', last_sync_at = ?, usage_cursor = ?, last_error = ?, sync_lease_until = NULL,
		    next_sync_at = ?, updated_at = ?
		WHERE workspace_id = ? AND id = ?`,
		now, f.to.Truncate(time.Hour), lastErr, now.Add(modelProviderSyncEvery), now, ws, id).Error
}

// upsertModelProviderUsage writes usage buckets in batches; a bucket read
// again replaces its stored totals (provider totals are final values).
func upsertModelProviderUsage(tx *gorm.DB, ws, id uuid.UUID, rows []modelprovider.UsageRow, now time.Time) error {
	const batch = 500
	for i := 0; i < len(rows); i += batch {
		end := i + batch
		if end > len(rows) {
			end = len(rows)
		}
		var sb strings.Builder
		args := make([]any, 0, (end-i)*11)
		for j, r := range rows[i:end] {
			if j > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString("(?, ?, ?, ?, ?, ?, ?::bigint, ?, ?, ?, ?)")
			args = append(args, ws, id, truncate(r.KeyID, 200), truncate(r.ProjectID, 200), truncate(r.Model, 200),
				r.BucketStart.UTC().Truncate(time.Hour), r.Requests, r.InputTokens, r.CachedInputTokens, r.OutputTokens, now)
		}
		if err := tx.Exec(`INSERT INTO model_provider_usage
			  (workspace_id, connection_id, provider_key_id, project_id, model, bucket_start, requests,
			   input_tokens, cached_input_tokens, output_tokens, updated_at)
			VALUES `+sb.String()+`
			ON CONFLICT (workspace_id, connection_id, provider_key_id, project_id, model, bucket_start) DO UPDATE SET
			  requests = excluded.requests, input_tokens = excluded.input_tokens,
			  cached_input_tokens = excluded.cached_input_tokens, output_tokens = excluded.output_tokens,
			  updated_at = excluded.updated_at`, args...).Error; err != nil {
			return fmt.Errorf("upsert usage: %w", err)
		}
	}
	return nil
}

/* ------------------------------ weak attribution ---------------------------- */

// ModelProviderLink is one weak tie of a provider key to the AWS estate.
type ModelProviderLink struct {
	Strength    string      `json:"strength"` // always weak
	Via         string      `json:"via"`      // secret_name | env_var_name
	Matched     string      `json:"matched"`  // key_name | project_name
	Name        string      `json:"name"`     // the secret or env-var NAME
	ConnectorID uuid.UUID   `json:"connector_id"`
	SecretARN   string      `json:"secret_arn,omitempty"`
	WorkloadIDs []uuid.UUID `json:"cloud_workload_ids"`
	IdentityIDs []uuid.UUID `json:"identity_ids"`
}

// attributionName is a name in the AWS estate a key could be tied by.
type attributionName struct {
	Via         string
	Name        string
	norm        string
	ConnectorID uuid.UUID
	SecretARN   string
	WorkloadIDs []uuid.UUID
	IdentityIDs []uuid.UUID
}

// attributionGeneric are words removed before deciding whether a name is
// specific enough to match (it must keep 4 characters).
var attributionGeneric = []string{"production", "workspace", "anthropic", "staging", "default", "project",
	"openai", "claude", "secret", "token", "admin", "prod", "test", "key", "api", "dev"}

func normalizeAttributionName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// attributionToken is the normalised name to look for, or "" when the name
// is too generic to tie anything ("Default project", "OPENAI_API_KEY").
func attributionToken(name string) string {
	n := normalizeAttributionName(name)
	rest := n
	for _, g := range attributionGeneric {
		rest = strings.ReplaceAll(rest, g, "")
	}
	if len(rest) < 4 {
		return ""
	}
	return n
}

// attributeKey is the weak links of one key: names in the estate that
// contain its key name or its project name.
func attributeKey(keyName, projectName string, names []attributionName) []ModelProviderLink {
	out := []ModelProviderLink{}
	try := []struct{ token, matched string }{
		{attributionToken(keyName), "key_name"},
		{attributionToken(projectName), "project_name"},
	}
	seen := map[string]bool{}
	for _, t := range try {
		if t.token == "" {
			continue
		}
		for _, n := range names {
			if !strings.Contains(n.norm, t.token) {
				continue
			}
			k := n.Via + "\x1f" + n.ConnectorID.String() + "\x1f" + n.SecretARN + "\x1f" + n.Name
			if len(n.WorkloadIDs) > 0 {
				k += "\x1f" + n.WorkloadIDs[0].String()
			}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, ModelProviderLink{Strength: "weak", Via: n.Via, Matched: t.matched, Name: n.Name,
				ConnectorID: n.ConnectorID, SecretARN: n.SecretARN, WorkloadIDs: nonNilUUIDs(n.WorkloadIDs),
				IdentityIDs: nonNilUUIDs(n.IdentityIDs)})
		}
	}
	return out
}

// loadAttributionNames reads, read-only, the workspace's AWS names a key
// could be tied by: Secrets Manager secret names with readers (the readers
// logic of agent_runtime_findings.go, without its model-key filter) and
// Lambda env-var names (newest generation). Never a value.
func loadAttributionNames(tx *gorm.DB, ws uuid.UUID) ([]attributionName, error) {
	var conns []arConnector
	if err := tx.Table("cloud_connector").Select("id, scope_id, attrs").
		Where("workspace_id = ? AND provider = ?", ws, models.CloudProviderAWS).Scan(&conns).Error; err != nil {
		return nil, fmt.Errorf("read connectors: %w", err)
	}
	var out []attributionName
	for _, c := range conns {
		secrets, err := loadSecretsNamed(tx, ws, c, func(string) bool { return true })
		if err != nil {
			return nil, err
		}
		var readers []uuid.UUID
		for _, s := range secrets.list {
			readers = append(readers, s.Readers...)
		}
		byIdentity := map[uuid.UUID][]uuid.UUID{}
		if len(readers) > 0 {
			var wls []struct {
				ID         uuid.UUID
				IdentityID uuid.UUID
			}
			if err := tx.Table("cloud_workload").Select("id, identity_id").
				Where("workspace_id = ? AND identity_id IN ?", ws, readers).Order("id").Scan(&wls).Error; err != nil {
				return nil, fmt.Errorf("read secret readers' workloads: %w", err)
			}
			for _, w := range wls {
				byIdentity[w.IdentityID] = append(byIdentity[w.IdentityID], w.ID)
			}
		}
		for _, s := range secrets.list {
			if len(s.Readers) == 0 {
				continue // no workload can read it: not a tie
			}
			var wls []uuid.UUID
			for _, r := range s.Readers {
				wls = append(wls, byIdentity[r]...)
			}
			out = append(out, attributionName{Via: "secret_name", Name: s.Name, norm: normalizeAttributionName(s.Name),
				ConnectorID: c.ID, SecretARN: s.ARN, WorkloadIDs: wls, IdentityIDs: s.Readers})
		}
	}
	var lambdas []struct {
		ID          uuid.UUID
		ConnectorID uuid.UUID
		IdentityID  *uuid.UUID
		Attrs       json.RawMessage
	}
	if err := tx.Table("cloud_workload w").Select("w.id, w.connector_id, w.identity_id, w.attrs").
		Where(`w.workspace_id = ? AND w.runtime_kind = ? AND w.last_seen_generation =
			(SELECT COALESCE(MAX(w2.last_seen_generation), 0) FROM cloud_workload w2
			  WHERE w2.workspace_id = w.workspace_id AND w2.connector_id = w.connector_id)`,
			ws, models.WorkloadLambdaFunction).Order("w.id").Scan(&lambdas).Error; err != nil {
		return nil, fmt.Errorf("read lambdas: %w", err)
	}
	for _, l := range lambdas {
		attrs := (&models.CloudWorkload{Attrs: l.Attrs}).AWSAttrs()
		var ids []uuid.UUID
		if l.IdentityID != nil {
			ids = []uuid.UUID{*l.IdentityID}
		}
		for _, v := range attrs.EnvVarNames {
			out = append(out, attributionName{Via: "env_var_name", Name: v, norm: normalizeAttributionName(v),
				ConnectorID: l.ConnectorID, WorkloadIDs: []uuid.UUID{l.ID}, IdentityIDs: ids})
		}
	}
	return out, nil
}

// loadSecretsNamed is loadModelKeySecrets (agent_runtime_findings.go) with a
// caller's name filter: the connector's Secrets Manager secret NAMES and the
// identities whose declared allow grants cover GetSecretValue on them.
func loadSecretsNamed(tx *gorm.DB, ws uuid.UUID, conn arConnector, keep func(string) bool) (*modelKeySecrets, error) {
	out := &modelKeySecrets{}
	byARN := map[string]*modelKeySecret{}
	add := func(arn, region string) {
		if arn == "" || byARN[arn] != nil {
			return
		}
		name := SecretNameFromARN(arn)
		if name == "" || !keep(name) {
			return
		}
		s := &modelKeySecret{ARN: arn, Name: name, Region: region}
		byARN[arn] = s
		out.list = append(out.list, s)
	}
	var latest []struct{ ScanRunID uuid.UUID }
	if err := tx.Table("cloud_resource_policy_coverage").Select("scan_run_id").
		Where("workspace_id = ? AND connector_id = ? AND resource_form = ? AND state IN ('complete','partial')",
			ws, conn.ID, "secretsmanager_secret").
		Order("collected_at DESC").Limit(1).Scan(&latest).Error; err != nil {
		return nil, fmt.Errorf("read secret coverage: %w", err)
	}
	if len(latest) == 1 {
		out.known = true
		var obs []struct {
			ResourceARN string
			Region      string
		}
		if err := tx.Table("cloud_resource_policy_observation").Select("resource_arn, region").
			Where("workspace_id = ? AND scan_run_id = ? AND resource_form = ?", ws, latest[0].ScanRunID, "secretsmanager_secret").
			Order("resource_arn").Scan(&obs).Error; err != nil {
			return nil, fmt.Errorf("read secrets: %w", err)
		}
		for _, o := range obs {
			add(o.ResourceARN, o.Region)
		}
	}
	var named []struct {
		ID       uuid.UUID
		NativeID string
	}
	if err := tx.Table("cloud_resource").Select("id, native_id").
		Where(`workspace_id = ? AND connector_id = ? AND kind = ? AND last_seen_generation =
			(SELECT COALESCE(MAX(r2.last_seen_generation), 0) FROM cloud_resource r2
			  WHERE r2.workspace_id = ? AND r2.connector_id = ?)`,
			ws, conn.ID, "secretsmanager_secret", ws, conn.ID).Scan(&named).Error; err != nil {
		return nil, fmt.Errorf("read named secrets: %w", err)
	}
	resourceARN := map[uuid.UUID]string{}
	for _, n := range named {
		resourceARN[n.ID] = n.NativeID
		add(n.NativeID, "")
	}
	if len(out.list) == 0 {
		return out, nil
	}
	var grants []struct {
		IdentityID uuid.UUID
		ResourceID *uuid.UUID
		ScopeKind  string
		Actions    string
	}
	if err := tx.Table("cloud_permission").
		Select("identity_id, resource_id, scope_kind, array_to_string(actions, ',') AS actions").
		Where("workspace_id = ? AND connector_id = ? AND effect = 'allow' AND scope_kind IN ('resource','account_wide')",
			ws, conn.ID).Scan(&grants).Error; err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}
	for _, g := range grants {
		if !grantsSecretRead(strings.Split(g.Actions, ",")) {
			continue
		}
		switch g.ScopeKind {
		case "account_wide":
			for _, s := range out.list {
				s.Readers = arAppendUniqueUUID(s.Readers, g.IdentityID)
			}
		case "resource":
			if g.ResourceID == nil {
				continue
			}
			if s := byARN[resourceARN[*g.ResourceID]]; s != nil {
				s.Readers = arAppendUniqueUUID(s.Readers, g.IdentityID)
			}
		}
	}
	return out, nil
}

/* --------------------------------- the finding ------------------------------ */

// unaccountedAction decides a key's finding: "open" (open or refresh),
// "resolve", or "" (leave as it is).
func unaccountedAction(linked, used7d, used30d, open bool) string {
	switch {
	case linked:
		if open {
			return "resolve"
		}
		return ""
	case used7d:
		return "open"
	case open && !used30d:
		return "resolve"
	}
	return ""
}

type modelProviderKeyRow struct {
	ProviderKeyID string
	Name          string
	ProjectID     string
	ProjectName   string
	OwnerType     string
	OwnerID       string
	OwnerName     string
	Status        string
	LastUsedAt    *time.Time
}

type modelProviderKeyUsage struct {
	ProviderKeyID string
	Requests      *int64
	InputTokens   int64
	OutputTokens  int64
	Models        string
	LastBucket    time.Time
	Recent        bool
}

// applyAttribution recomputes every key's links and the connection's
// unaccounted_model_usage findings.
func (s *ModelProviderService) applyAttribution(tx *gorm.DB, ws, id uuid.UUID, cl modelProviderClaim, now time.Time, res *ModelProviderSyncResult) error {
	names, err := loadAttributionNames(tx, ws)
	if err != nil {
		return err
	}
	var keys []modelProviderKeyRow
	if err := tx.Raw(`SELECT provider_key_id, name, project_id, project_name, owner_type, owner_id, owner_name, status, last_used_at
	                   FROM model_provider_key WHERE workspace_id = ? AND connection_id = ? ORDER BY provider_key_id`, ws, id).Scan(&keys).Error; err != nil {
		return err
	}
	links := map[string][]ModelProviderLink{}
	type upd struct{ id, links string }
	var updates []upd
	for _, k := range keys {
		l := attributeKey(k.Name, k.ProjectName, names)
		links[k.ProviderKeyID] = l
		if len(l) > 0 {
			res.KeysLinked++
		}
		raw, _ := json.Marshal(l)
		updates = append(updates, upd{k.ProviderKeyID, string(raw)})
	}
	for i := 0; i < len(updates); i += 500 {
		end := i + 500
		if end > len(updates) {
			end = len(updates)
		}
		var sb strings.Builder
		args := []any{now}
		for j, u := range updates[i:end] {
			if j > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString("(?::text, ?::jsonb)")
			args = append(args, u.id, u.links)
		}
		args = append(args, ws, id)
		if err := tx.Exec(`UPDATE model_provider_key k SET links = v.links, updated_at = ?
			  FROM (VALUES `+sb.String()+`) AS v(provider_key_id, links)
			 WHERE k.workspace_id = ? AND k.connection_id = ? AND k.provider_key_id = v.provider_key_id
			   AND k.links IS DISTINCT FROM v.links`, args...).Error; err != nil {
			return fmt.Errorf("links: %w", err)
		}
	}

	var usage []modelProviderKeyUsage
	if err := tx.Raw(`SELECT provider_key_id,
		       CASE WHEN count(requests) FILTER (WHERE bucket_start >= ?) = 0 THEN NULL
		            ELSE sum(requests) FILTER (WHERE bucket_start >= ?) END AS requests,
		       COALESCE(sum(input_tokens) FILTER (WHERE bucket_start >= ?), 0) AS input_tokens,
		       COALESCE(sum(output_tokens) FILTER (WHERE bucket_start >= ?), 0) AS output_tokens,
		       COALESCE(string_agg(DISTINCT model, ',') FILTER (WHERE bucket_start >= ? AND model <> ''), '') AS models,
		       max(bucket_start) AS last_bucket,
		       bool_or(bucket_start >= ?) AS recent
		  FROM model_provider_usage
		 WHERE workspace_id = ? AND connection_id = ? AND provider_key_id <> '' AND bucket_start >= ?
		   AND (input_tokens > 0 OR output_tokens > 0 OR COALESCE(requests, 0) > 0)
		 GROUP BY provider_key_id`,
		now.Add(-unaccountedWindow), now.Add(-unaccountedWindow), now.Add(-unaccountedWindow), now.Add(-unaccountedWindow),
		now.Add(-unaccountedWindow), now.Add(-unaccountedWindow), ws, id, now.Add(-unaccountedResolve)).Scan(&usage).Error; err != nil {
		return fmt.Errorf("key usage: %w", err)
	}
	byKey := map[string]modelProviderKeyUsage{}
	for _, u := range usage {
		byKey[u.ProviderKeyID] = u
	}
	prefix := unaccountedSubjectPrefix(id)
	var open []string
	if err := tx.Raw(`SELECT subject_key FROM agent_finding
	                   WHERE workspace_id = ? AND provider_connection_id = ? AND kind = ? AND state = 'open'`,
		ws, id, FindingUnaccountedModelUsage).Scan(&open).Error; err != nil {
		return err
	}
	isOpen := map[string]bool{}
	for _, o := range open {
		isOpen[strings.TrimPrefix(o, prefix)] = true
	}
	keyByID := map[string]modelProviderKeyRow{}
	for _, k := range keys {
		keyByID[k.ProviderKeyID] = k
	}
	ids := map[string]bool{}
	for k := range keyByID {
		ids[k] = true
	}
	for k := range isOpen {
		ids[k] = true
	}
	sorted := make([]string, 0, len(ids))
	for k := range ids {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, keyID := range sorted {
		u, used := byKey[keyID]
		action := unaccountedAction(len(links[keyID]) > 0, used && u.Recent, used, isOpen[keyID])
		switch action {
		case "open":
			k := keyByID[keyID]
			models := []string{}
			if u.Models != "" {
				models = strings.Split(u.Models, ",")
			}
			subject := map[string]any{"provider": cl.Provider, "connection_id": id, "connection_name": cl.DisplayName,
				"provider_key_id": keyID, "key_name": k.Name, "project_id": k.ProjectID, "project_name": k.ProjectName,
				"owner": map[string]any{"type": k.OwnerType, "id": k.OwnerID, "name": k.OwnerName}, "key_status": k.Status}
			evidence := map[string]any{"window_days": 7, "requests": u.Requests, "input_tokens": u.InputTokens,
				"output_tokens": u.OutputTokens, "models": models, "last_used_at": u.LastBucket,
				"attribution":   "weak: no Secrets Manager secret name (readable by a workload) or Lambda environment variable name in the workspace's AWS accounts contains the key name or the project name",
				"names_checked": len(names), "value_read": false}
			subj, _ := json.Marshal(subject)
			ev, _ := json.Marshal(evidence)
			if err := tx.Exec(`INSERT INTO agent_finding
				  (workspace_id, connector_id, provider_connection_id, kind, subject_key, identity_id, subject, evidence,
				   state, first_seen, last_seen, resolved_at, created_at, updated_at)
				VALUES (?, NULL, ?, ?, ?, NULL, ?::jsonb, ?::jsonb, 'open', ?, ?, NULL, ?, ?)
				ON CONFLICT (workspace_id, kind, subject_key) DO UPDATE SET
				  provider_connection_id = excluded.provider_connection_id, subject = excluded.subject,
				  evidence = excluded.evidence, state = 'open', last_seen = excluded.last_seen,
				  resolved_at = NULL, updated_at = excluded.updated_at`,
				ws, id, FindingUnaccountedModelUsage, prefix+keyID, string(subj), string(ev), now, now, now, now).Error; err != nil {
				return fmt.Errorf("open finding: %w", err)
			}
			res.FindingsOpen++
		case "resolve":
			reason := "no_usage_30_days"
			if len(links[keyID]) > 0 {
				reason = "linked"
			}
			r := tx.Exec(`UPDATE agent_finding SET state = 'resolved', resolved_at = ?, updated_at = ?,
				  evidence = evidence || jsonb_build_object('resolved_reason', ?::text)
				WHERE workspace_id = ? AND kind = ? AND subject_key = ? AND state = 'open'`,
				now, now, reason, ws, FindingUnaccountedModelUsage, prefix+keyID)
			if r.Error != nil {
				return fmt.Errorf("resolve finding: %w", r.Error)
			}
			res.FindingsResolved += int(r.RowsAffected)
		}
	}
	return nil
}
