package services

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

/* agent_runtime_joins.go: the rows the usage reconciliation joins (W6, C3-C5).

   - Join settings (agent_join_setting): a workspace's egress hosts (kept
     beside the model provider list) and the flow-log log groups to read per
     AWS connector and region.
   - DNS lookups (agent_dns_lookup): written by the Route 53 Resolver read
     (agent_runtime_dns.go) in the same transaction as its findings: per
     minute, source, resolved holder, name and first answer, for provider and
     egress hosts only.
   - Flow summaries (agent_flow_summary): CollectFlows reads a connector's
     configured VPC flow-log group for the addresses provider / egress hosts
     resolved to (from the stored lookups), per minute, and names the source's
     holder from the lookups of the same address.
   Every statement runs under row-level security for one workspace. */

const (
	joinMaxEgressHosts   = 200
	joinMaxFlowLogGroups = 50
	// joinDestinationLookback is how far back resolved answers count as
	// flow destinations.
	joinDestinationLookback = 7 * 24 * time.Hour
	// dnsLookupRetention bounds how long lookup and flow rows are kept.
	joinRowRetention = 30 * 24 * time.Hour
)

// AgentFlowLogGroup is one flow-log log group to read.
type AgentFlowLogGroup struct {
	ConnectorID uuid.UUID `json:"connector_id"`
	Region      string    `json:"region"`
	LogGroup    string    `json:"log_group"`
}

// AgentJoinSettings are a workspace's join settings.
type AgentJoinSettings struct {
	EgressHosts   []string            `json:"egress_hosts"`
	FlowLogGroups []AgentFlowLogGroup `json:"flow_log_groups"`
	Version       int                 `json:"version"`
	UpdatedBy     *uuid.UUID          `json:"updated_by,omitempty"`
	UpdatedAt     *time.Time          `json:"updated_at,omitempty"`
}

// AgentJoinSettingsInput replaces the settings; Version (0: none yet) must
// be the current one when given.
type AgentJoinSettingsInput struct {
	EgressHosts   []string            `json:"egress_hosts"`
	FlowLogGroups []AgentFlowLogGroup `json:"flow_log_groups"`
	Version       *int                `json:"version"`
}

func loadJoinSettings(tx *gorm.DB, ws uuid.UUID) (AgentJoinSettings, error) {
	out := AgentJoinSettings{EgressHosts: []string{}, FlowLogGroups: []AgentFlowLogGroup{}}
	var rows []struct {
		EgressHosts   string
		FlowLogGroups string
		Version       int
		UpdatedBy     *uuid.UUID
		UpdatedAt     time.Time
	}
	if err := tx.Raw(`SELECT egress_hosts::text AS egress_hosts, flow_log_groups::text AS flow_log_groups, version,
	                         updated_by, updated_at
	                    FROM agent_join_setting WHERE workspace_id = ?`, ws).Scan(&rows).Error; err != nil {
		return out, err
	}
	if len(rows) == 0 {
		return out, nil
	}
	r := rows[0]
	_ = json.Unmarshal([]byte(r.EgressHosts), &out.EgressHosts)
	_ = json.Unmarshal([]byte(r.FlowLogGroups), &out.FlowLogGroups)
	at := r.UpdatedAt.UTC()
	out.Version, out.UpdatedBy, out.UpdatedAt = r.Version, r.UpdatedBy, &at
	return out, nil
}

var reLogGroupARN = regexp.MustCompile(`^arn:aws[a-z-]*:logs:([a-z0-9-]+):[0-9]{12}:log-group:[A-Za-z0-9_./#-]{1,512}$`)

// AgentRuntimeJoinService serves the join settings and the flow collection.
type AgentRuntimeJoinService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentRuntimeJoinService builds the service over db.
func NewAgentRuntimeJoinService(db *gorm.DB) *AgentRuntimeJoinService {
	return &AgentRuntimeJoinService{db: db, now: time.Now}
}

// Settings reads ws's join settings (defaults when unset).
func (s *AgentRuntimeJoinService) Settings(ctx context.Context, ws uuid.UUID) (AgentJoinSettings, error) {
	var out AgentJoinSettings
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = loadJoinSettings(tx, ws)
		return err
	})
	return out, err
}

// PutSettings replaces ws's join settings.
func (s *AgentRuntimeJoinService) PutSettings(ctx context.Context, ws, actor uuid.UUID, in AgentJoinSettingsInput) (AgentJoinSettings, AgentJoinSettings, error) {
	var before, after AgentJoinSettings
	if len(in.EgressHosts) > joinMaxEgressHosts {
		return before, after, GovBadParam("egress_hosts", fmt.Sprintf("at most %d egress hosts.", joinMaxEgressHosts))
	}
	if len(in.FlowLogGroups) > joinMaxFlowLogGroups {
		return before, after, GovBadParam("flow_log_groups", fmt.Sprintf("at most %d flow-log groups.", joinMaxFlowLogGroups))
	}
	hosts := []string{}
	seen := map[string]bool{}
	for _, h := range in.EgressHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if awsdiscovery.EgressHostPattern(h) == "" {
			return before, after, GovBadParam("egress_hosts", "each egress host is a DNS name (api.example.com) or *.example.com.")
		}
		if _, _, ok := awsdiscovery.MatchModelEndpoint(strings.TrimPrefix(h, "*.")); ok {
			continue // already on the provider list
		}
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	groups := []AgentFlowLogGroup{}
	for _, g := range in.FlowLogGroups {
		g.LogGroup = strings.TrimSuffix(strings.TrimSpace(g.LogGroup), ":*")
		m := reLogGroupARN.FindStringSubmatch(g.LogGroup)
		if m == nil || g.ConnectorID == uuid.Nil {
			return before, after, GovBadParam("flow_log_groups", "each entry is {connector_id, region, log_group: arn:aws:logs:<region>:<account>:log-group:<name>}.")
		}
		if g.Region == "" {
			g.Region = m[1]
		}
		if g.Region != m[1] {
			return before, after, GovBadParam("flow_log_groups", "region must be the log group's region.")
		}
		groups = append(groups, g)
	}
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = loadJoinSettings(tx, ws); err != nil {
			return err
		}
		if in.Version != nil && *in.Version != before.Version {
			return govConflict(GovCodeVersionConflict, "The settings changed since you opened them.", map[string]any{"version": before.Version})
		}
		for _, g := range groups {
			var n int64
			if err := tx.Raw(`SELECT count(*) FROM cloud_connector WHERE workspace_id = ? AND id = ?`, ws, g.ConnectorID).Scan(&n).Error; err != nil {
				return err
			}
			if n == 0 {
				return GovBadParam("flow_log_groups", "connector_id must be one of the workspace's connectors.")
			}
		}
		if err := tx.Exec(`INSERT INTO agent_join_setting (workspace_id, egress_hosts, flow_log_groups, updated_by)
		                   VALUES (?, ?::jsonb, ?::jsonb, ?)
		                   ON CONFLICT (workspace_id) DO UPDATE SET egress_hosts = EXCLUDED.egress_hosts,
		                       flow_log_groups = EXCLUDED.flow_log_groups, updated_by = EXCLUDED.updated_by,
		                       updated_at = now(), version = agent_join_setting.version + 1`,
			ws, agwJSON(hosts), agwJSON(groups), actor).Error; err != nil {
			return err
		}
		after, err = loadJoinSettings(tx, ws)
		return err
	})
	return before, after, err
}

/* ---------------------------------- DNS rows -------------------------------- */

// joinEgressHosts reads ws's egress hosts (the DNS read adds them to its query).
func joinEgressHosts(ctx context.Context, db *gorm.DB, ws uuid.UUID) ([]string, error) {
	var out []string
	err := tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		st, err := loadJoinSettings(tx, ws)
		out = st.EgressHosts
		return err
	})
	return out, err
}

// insertDNSLookupRows writes one region's per-minute lookups (provider and
// egress hosts) with their resolved holder, in the DNS write's transaction.
// A minute read in two windows adds up.
func insertDNSLookupRows(tx *gorm.DB, w dnsWrite, inv dnsInventory) (int, error) {
	type row struct {
		l        awsdiscovery.DNSMinuteLookup
		eni      string
		holder   *uuid.UUID
		ref, arn string
	}
	var rows []row
	for _, r := range w.Reads {
		if r.Err != nil || r.Skipped {
			continue
		}
		for _, l := range r.Read.Lookups {
			attr := w.Sources[dnsSourceKey{l.VPCID, l.SrcAddr}]
			agg := awsdiscovery.DNSLookupAggregate{SrcAddr: l.SrcAddr, InstanceID: l.InstanceID, VPCID: l.VPCID,
				Domain: l.Domain, FirstSeen: l.Minute, LastSeen: l.Minute.Add(59 * time.Second)}
			subj := attributeDNSLookups(agg, attr, inv, w.Region, w.Account, w.Partition)
			rw := row{l: l, ref: subj.Key, arn: r.Group.ARN}
			if id, ok := subj.Subject["cloud_workload_id"].(uuid.UUID); ok {
				rw.holder = &id
			}
			if attr.ENI != nil {
				rw.eni = attr.ENI.ID
			}
			rows = append(rows, rw)
		}
	}
	const batch = 200
	for i := 0; i < len(rows); i += batch {
		end := i + batch
		if end > len(rows) {
			end = len(rows)
		}
		var sb strings.Builder
		args := make([]any, 0, (end-i)*16)
		for j, r := range rows[i:end] {
			if j > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString("(?, ?, 'route53', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
			args = append(args, w.WorkspaceID, w.ConnectorID, w.Region, r.l.Minute, r.l.SrcAddr, r.eni, r.l.InstanceID,
				r.l.VPCID, r.holder, truncate(r.ref, 512), r.l.Domain, r.l.HostKind, r.l.Provider, r.l.Answer, r.l.Queries, r.arn)
		}
		if err := tx.Exec(`INSERT INTO agent_dns_lookup (workspace_id, connector_id, source, region, observed_at, src_ip, src_eni,
		                       src_instance, vpc_id, holder_workload_id, holder_ref, query_name, host_kind, provider, answer_ip,
		                       queries, log_group_arn)
		                   VALUES `+sb.String()+`
		                   ON CONFLICT (workspace_id, connector_id, source, observed_at, src_ip, src_instance, vpc_id, query_name, answer_ip)
		                   DO UPDATE SET queries = agent_dns_lookup.queries + EXCLUDED.queries,
		                       holder_workload_id = COALESCE(EXCLUDED.holder_workload_id, agent_dns_lookup.holder_workload_id),
		                       holder_ref = EXCLUDED.holder_ref, src_eni = EXCLUDED.src_eni`, args...).Error; err != nil {
			return 0, fmt.Errorf("dns lookups: %w", err)
		}
	}
	if err := tx.Exec(`DELETE FROM agent_dns_lookup WHERE workspace_id = ? AND connector_id = ? AND observed_at < ?`,
		w.WorkspaceID, w.ConnectorID, w.Now.Add(-joinRowRetention)).Error; err != nil {
		return 0, err
	}
	return len(rows), nil
}

/* ----------------------------------- flows ---------------------------------- */

// FlowCollectResult counts one collection.
type FlowCollectResult struct {
	LogGroups    int
	Destinations int
	Rows         int
	Errors       []string
}

type flowDest struct {
	AnswerIP  string
	QueryName string
	Provider  string
}

// CollectFlows reads the flow-log groups configured for (connector,
// region) since their cursors, filtered to the addresses provider and
// egress hosts resolved to, and stores per-minute summaries. logs is the
// region's Logs Insights client.
func (s *AgentRuntimeJoinService) CollectFlows(ctx context.Context, ws, connectorID uuid.UUID, region string,
	logs awsdiscovery.LogsInsightsAPI, sleep func(context.Context, time.Duration) error) (FlowCollectResult, error) {
	var res FlowCollectResult
	now := s.now().UTC()
	var groups []AgentFlowLogGroup
	var dests []flowDest
	cursors := map[string]time.Time{}
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		st, err := loadJoinSettings(tx, ws)
		if err != nil {
			return err
		}
		for _, g := range st.FlowLogGroups {
			if g.ConnectorID == connectorID && g.Region == region {
				groups = append(groups, g)
			}
		}
		if len(groups) == 0 {
			return nil
		}
		if err := tx.Raw(`SELECT answer_ip, (array_agg(query_name ORDER BY observed_at DESC))[1] AS query_name,
		                         (array_agg(provider ORDER BY observed_at DESC))[1] AS provider
		                    FROM agent_dns_lookup WHERE workspace_id = ? AND answer_ip <> '' AND observed_at >= ?
		                   GROUP BY answer_ip ORDER BY max(observed_at) DESC LIMIT ?`,
			ws, now.Add(-joinDestinationLookback), awsdiscovery.MaxFlowDestinations).Scan(&dests).Error; err != nil {
			return err
		}
		var cs []struct {
			LogGroupARN string
			ReadTo      time.Time
		}
		if err := tx.Raw(`SELECT log_group_arn, read_to FROM cloud_dns_cursor
		                   WHERE workspace_id = ? AND connector_id = ? AND region = ? AND stream = 'flow'`,
			ws, connectorID, region).Scan(&cs).Error; err != nil {
			return err
		}
		for _, c := range cs {
			cursors[c.LogGroupARN] = c.ReadTo.UTC()
		}
		return nil
	}); err != nil {
		return res, err
	}
	if len(groups) == 0 {
		return res, nil
	}
	byIP := map[string]flowDest{}
	ips := make([]string, 0, len(dests))
	for _, d := range dests {
		byIP[d.AnswerIP] = d
		ips = append(ips, d.AnswerIP)
	}
	res.Destinations = len(ips)
	if len(ips) == 0 {
		// Nothing resolved yet: nothing to filter on, and the cursors stay
		// where they are so the window is read once destinations are known.
		return res, nil
	}
	reader := awsdiscovery.NewFlowLogReader(logs)
	if sleep != nil {
		reader = reader.WithSleep(sleep)
	}
	for _, g := range groups {
		res.LogGroups++
		w := awsdiscovery.DNSWindowFor(cursors[g.LogGroup], now)
		read, err := reader.ReadFlows(ctx, g.LogGroup, w, ips)
		if err != nil {
			res.Errors = append(res.Errors, g.LogGroup+": "+err.Error())
			continue
		}
		n, err := s.storeFlows(ctx, ws, connectorID, region, g.LogGroup, read, byIP, now)
		if err != nil {
			return res, err
		}
		res.Rows += n
	}
	return res, nil
}

func (s *AgentRuntimeJoinService) storeFlows(ctx context.Context, ws, connectorID uuid.UUID, region, logGroup string,
	read awsdiscovery.FlowRead, byIP map[string]flowDest, now time.Time) (int, error) {
	n := 0
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		srcs := map[string]bool{}
		for _, r := range read.Rows {
			if r.SrcAddr != "" {
				srcs[r.SrcAddr] = true
			}
		}
		type holder struct {
			SrcIP            string
			HolderWorkloadID *uuid.UUID
			HolderRef        string
		}
		holders := map[string]holder{}
		if len(srcs) > 0 {
			var hs []holder
			if err := tx.Raw(`SELECT DISTINCT ON (src_ip) src_ip, holder_workload_id, holder_ref FROM agent_dns_lookup
			                   WHERE workspace_id = ? AND connector_id = ? AND src_ip IN ?
			                   ORDER BY src_ip, observed_at DESC`, ws, connectorID, sortedKeys(srcs)).Scan(&hs).Error; err != nil {
				return err
			}
			for _, h := range hs {
				holders[h.SrcIP] = h
			}
		}
		for _, r := range read.Rows {
			d := byIP[r.DstAddr]
			h := holders[r.SrcAddr]
			if err := tx.Exec(`INSERT INTO agent_flow_summary (workspace_id, connector_id, source, region, minute, src_ip, src_eni,
			                       holder_workload_id, holder_ref, dst_ip, dst_host, provider, bytes_out, packets, log_group_arn)
			                   VALUES (?, ?, 'vpc', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			                   ON CONFLICT (workspace_id, connector_id, source, minute, src_ip, src_eni, dst_ip) DO UPDATE SET
			                       bytes_out = agent_flow_summary.bytes_out + EXCLUDED.bytes_out,
			                       packets = agent_flow_summary.packets + EXCLUDED.packets,
			                       holder_workload_id = COALESCE(EXCLUDED.holder_workload_id, agent_flow_summary.holder_workload_id)`,
				ws, connectorID, region, r.Minute, r.SrcAddr, r.ENI, h.HolderWorkloadID, truncate(h.HolderRef, 512), r.DstAddr,
				d.QueryName, d.Provider, r.BytesOut, r.Packets, logGroup).Error; err != nil {
				return err
			}
			n++
		}
		if err := tx.Exec(`DELETE FROM agent_flow_summary WHERE workspace_id = ? AND connector_id = ? AND minute < ?`,
			ws, connectorID, now.Add(-joinRowRetention)).Error; err != nil {
			return err
		}
		reason := ""
		if read.Truncated {
			reason = "truncated"
		}
		return tx.Exec(`INSERT INTO cloud_dns_cursor (workspace_id, connector_id, region, stream, log_group_arn, window_from,
		                    covered_from, read_to, partial, partial_reason, groups, last_error, last_attempt_at, updated_at)
		                VALUES (?, ?, ?, 'flow', ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
		                ON CONFLICT (workspace_id, connector_id, region, stream, log_group_arn) DO UPDATE SET
		                    window_from = EXCLUDED.window_from, read_to = EXCLUDED.read_to, partial = EXCLUDED.partial,
		                    partial_reason = EXCLUDED.partial_reason, groups = EXCLUDED.groups, last_error = '',
		                    last_attempt_at = EXCLUDED.last_attempt_at, updated_at = EXCLUDED.updated_at`,
			ws, connectorID, region, logGroup, read.Window.From, read.Window.From, read.Window.To, read.Truncated, reason,
			len(read.Rows), now, now).Error
	})
	return n, err
}
