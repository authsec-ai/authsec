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

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

/* agent_runtime_dns.go is DNS-based detection of direct model-provider calls
   (SPEC-agent-runtime-visibility.md §11).

   Per region of an AWS scan: the Route 53 Resolver query logging
   configurations and the VPCs they log; for each CloudWatch Logs destination,
   the lookups of the model-endpoint list since the last read (Logs Insights,
   filtered in the query, so no other DNS data is read); the workload behind
   each source address; and one agent_finding of kind ai_network_traffic per
   workload (or, for an address nothing explains, per VPC). A finding is
   resolved when its log groups have been read without a gap for 30 days after
   its last lookup.

   Nothing here fails the scan: a failure is coverage
   (dns-query-logs:<region>) and a warning. */

// FindingAINetworkTraffic is the agent_finding kind this file writes.
const FindingAINetworkTraffic = "ai_network_traffic"

// findingKindsOutsideInference are agent_finding kinds another writer owns:
// the inference pass (applyFindings) neither opens nor resolves them.
var findingKindsOutsideInference = map[string]bool{FindingAINetworkTraffic: true}

func init() { FindingKinds[FindingAINetworkTraffic] = true }

const (
	// DNSTrafficResolveAfter is how long a finding must go without a lookup,
	// read without a gap, before it is resolved.
	DNSTrafficResolveAfter = 30 * 24 * time.Hour
	// dnsMaxLogGroupsPerRegion bounds the Logs Insights queries one scan runs
	// per region (each is charged per GB scanned).
	dnsMaxLogGroupsPerRegion = 10
	// dnsMaxSourcesPerFinding bounds the srcaddr references one finding keeps.
	dnsMaxSourcesPerFinding = 50
	// envDNSQueryLogs turns the read off for a deployment ("off").
	envDNSQueryLogs = "AUTHSEC_AWS_DNS_QUERY_LOGS"
	// dnsEvidenceSource names where the evidence came from.
	dnsEvidenceSource = "route53_resolver_query_logs"
)

// dnsLimitations travel with every finding: what it cannot claim.
var dnsLimitations = []string{
	"Lambda functions not attached to a VPC and workloads using a resolver other than the Route 53 Resolver are not visible",
	"attribution by private address names the network interface holding the address at scan time",
	"a lookup is not a call: it shows the workload resolved the provider's API host",
}

// DNSClients are one region's clients for the DNS read.
type DNSClients struct {
	Resolver awsdiscovery.ResolverQueryLogAPI
	Logs     awsdiscovery.LogsInsightsAPI
	ENI      awsdiscovery.NetworkInterfaceAPI
	ECS      awsdiscovery.ECSTaskAPI
}

// dnsScanConfig holds the DNS read's test seams.
type dnsScanConfig struct {
	apis  func(region string) DNSClients
	clock func() time.Time
	sleep func(context.Context, time.Duration) error
}

// WithDNSAPIs installs the DNS read's clients per region (tests).
func (s *AWSWorkloadScanner) WithDNSAPIs(f func(region string) DNSClients) *AWSWorkloadScanner {
	s.dns.apis = f
	return s
}

// WithDNSClock replaces the DNS read's clock and polling delay (tests).
func (s *AWSWorkloadScanner) WithDNSClock(now func() time.Time, sleep func(context.Context, time.Duration) error) *AWSWorkloadScanner {
	s.dns.clock, s.dns.sleep = now, sleep
	return s
}

func dnsQueryLogsDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(envDNSQueryLogs)), "off")
}

// dnsClientsFor returns the region's clients and the connector's recorded
// template version. ok is false when the scan runs on injected test clients
// with none for DNS: the read is then not attempted and reports nothing.
func (s *AWSWorkloadScanner) dnsClientsFor(ctx context.Context, ws, connectorID uuid.UUID, region string) (DNSClients, string, bool, error) {
	if s.dns.apis != nil {
		version := ""
		if s.onboarding != nil {
			if c, err := s.connector(ws, connectorID); err == nil {
				version = c.AWSAttrs().StackReportedTemplateVersion()
			}
		}
		return s.dns.apis(region), version, true, nil
	}
	if s.regionalAPIs != nil || s.lambdaAPI != nil || s.ecsAPI != nil || s.ec2API != nil ||
		s.bedrockAPI != nil || s.agentCoreAPI != nil || s.cloudTrailAPI != nil || s.onboarding == nil {
		return DNSClients{}, "", false, nil
	}
	cfg, c, err := s.onboarding.ConfigForConnector(ctx, ws, connectorID, region)
	if err != nil {
		return DNSClients{}, "", true, err
	}
	return DNSClients{
		Resolver: awsdiscovery.NewResolverQueryLogClient(cfg), Logs: awsdiscovery.NewLogsInsightsClient(cfg),
		ENI: awsdiscovery.NewNetworkInterfaceClient(cfg), ECS: awsdiscovery.NewECSTaskClient(cfg),
	}, c.AWSAttrs().StackReportedTemplateVersion(), true, nil
}

/* ------------------------------- the region pass ---------------------------- */

// dnsLogGroup is one CloudWatch Logs destination to read, with the VPCs and
// configurations that write to it.
type dnsLogGroup struct {
	ARN     string
	VPCs    []string
	Configs []string
}

// dnsUnread is one configuration not read, and why.
type dnsUnread struct {
	Config, Kind, Destination, Reason string
	VPCs                              []string
}

// dnsLogGroupRead is one log group's read this scan.
type dnsLogGroupRead struct {
	Group dnsLogGroup
	Read  awsdiscovery.DNSQueryRead
	Err   error
	// Skipped: the window was empty (read to the mark already).
	Skipped bool
}

// scanDNSQueryLogs is the region's DNS read (§11). Called once per region
// after the CloudTrail passes.
func (s *AWSWorkloadScanner) scanDNSQueryLogs(
	ctx context.Context, workspaceID uuid.UUID, snapshot *IAMSnapshot,
	scope arnScope, region string, out *WorkloadSnapshot,
) {
	key := models.SurfaceRegional(models.SurfaceDNSQueryLogsPrefix, region)
	if dnsQueryLogsDisabled() {
		out.Surfaces[key] = models.SurfaceCoverage{State: models.CloudCoverageNotSelected,
			Error: "reading Route 53 Resolver query logs is turned off on this AuthSec deployment (" + envDNSQueryLogs + "=off)"}
		return
	}
	clients, templateVersion, ok, err := s.dnsClientsFor(ctx, workspaceID, snapshot.ConnectorID, region)
	if !ok {
		return
	}
	warn := func(format string, args ...any) {
		msg := fmt.Sprintf("dns %s: ", region) + fmt.Sprintf(format, args...)
		log.Printf("aws workload scan: %s", msg)
		out.Warnings = append(out.Warnings, msg)
	}
	if err != nil {
		out.Surfaces[key] = surfaceResult(0, err)
		return
	}
	out.Surfaces[models.SurfaceDNSBlindSpots] = models.DNSBlindSpotsCoverage()

	reader := awsdiscovery.NewDNSQueryLogReader(clients.Resolver, clients.Logs)
	if s.dns.sleep != nil {
		reader = reader.WithSleep(s.dns.sleep)
	}
	configs, err := reader.Configs(ctx)
	if err != nil {
		out.Surfaces[key] = withDNSTemplateNote(surfaceResult(0, err), templateVersion)
		return
	}
	groups, unread := planDNSDestinations(configs, region, scope.account)
	if len(unread) > 0 {
		out.Surfaces[models.SurfaceRegional(models.SurfaceDNSQueryLogsUnreadPrefix, region)] = unreadDNSCoverage(unread)
	}
	if len(groups) == 0 {
		msg := fmt.Sprintf("no VPC of this account in %s logs Route 53 Resolver queries to CloudWatch Logs; "+
			"model-provider lookups cannot be read here (enable Resolver query logging to a CloudWatch Logs log group)", region)
		if len(unread) > 0 {
			msg = fmt.Sprintf("%d query logging configuration(s) in %s deliver to destinations AuthSec does not read (%s); "+
				"no CloudWatch Logs destination to read", len(unread), region,
				models.SurfaceRegional(models.SurfaceDNSQueryLogsUnreadPrefix, region))
		}
		out.Surfaces[key] = models.SurfaceCoverage{State: models.CloudCoverageUnsupported, Error: msg}
		return
	}
	var skipped []dnsLogGroup
	if len(groups) > dnsMaxLogGroupsPerRegion {
		groups, skipped = groups[:dnsMaxLogGroupsPerRegion], groups[dnsMaxLogGroupsPerRegion:]
	}

	store := dnsEvidenceStore{db: s.db, fence: s.fence}
	// TENANT-EXEMPT: a nil check on the handle, no statement runs on it.
	if s.db == nil {
		out.Surfaces[key] = models.SurfaceCoverage{State: models.CloudCoverageDenied,
			Error: "no database to keep the DNS read cursors in"}
		return
	}
	cursors, err := store.Cursors(ctx, workspaceID, snapshot.ConnectorID, region)
	if err != nil {
		warn("reading the DNS cursors: %v; DNS read skipped this scan", err)
		out.Surfaces[key] = models.SurfaceCoverage{State: models.CloudCoverageDenied,
			Error: "reading the DNS read cursors: " + err.Error()}
		return
	}
	now := time.Now().UTC()
	if s.dns.clock != nil {
		now = s.dns.clock().UTC()
	}
	reads := make([]dnsLogGroupRead, 0, len(groups))
	for _, g := range groups {
		w := awsdiscovery.DNSWindowFor(cursors[g.ARN].ReadTo, now)
		if w.Empty() {
			reads = append(reads, dnsLogGroupRead{Group: g, Skipped: true, Read: awsdiscovery.DNSQueryRead{LogGroup: g.ARN, Window: w, Settled: true}})
			continue
		}
		read, rerr := reader.ReadModelEndpointLookups(ctx, g.ARN, w)
		if rerr != nil {
			warn("reading %s: %v", g.ARN, rerr)
		}
		reads = append(reads, dnsLogGroupRead{Group: g, Read: read, Err: rerr})
	}

	sources := resolveDNSSources(ctx, clients, reads, warn)
	res, werr := store.Record(ctx, dnsWrite{
		WorkspaceID: workspaceID, ConnectorID: snapshot.ConnectorID, Region: region, Account: scope.account,
		Partition: scope.partition, Reads: reads, Sources: sources, Now: now,
	})
	if werr != nil {
		warn("recording DNS evidence: %v", werr)
	}
	out.DNSTrafficFindings += res.Written
	out.Surfaces[key] = withDNSTemplateNote(dnsCoverage(reads, skipped, werr), templateVersion)
}

// planDNSDestinations sorts the configurations into log groups to read and
// configurations not read. Only configurations logging at least one VPC of
// this account count; a log group written by several is read once.
func planDNSDestinations(configs []awsdiscovery.QueryLogConfig, region, account string) ([]dnsLogGroup, []dnsUnread) {
	byARN := map[string]*dnsLogGroup{}
	var order []string
	var unread []dnsUnread
	for _, c := range configs {
		vpcs := c.ActiveVPCs()
		if len(vpcs) == 0 {
			continue
		}
		name := c.Name
		if name == "" {
			name = c.ID
		}
		u := dnsUnread{Config: name, Kind: c.DestinationKind, Destination: c.DestinationARN, VPCs: vpcs}
		switch {
		case c.DestinationKind == awsdiscovery.DNSDestinationS3, c.DestinationKind == awsdiscovery.DNSDestinationFirehose:
			u.Reason = "unsupported destination (" + c.DestinationKind + "), not read"
		case c.DestinationKind != awsdiscovery.DNSDestinationCloudWatchLogs:
			u.Reason = "unrecognised destination, not read"
		case c.DestinationRegion != region:
			u.Reason = "the log group is in region " + c.DestinationRegion + ", not read from " + region
		case account != "" && c.DestinationAccount != account:
			u.Reason = "the log group is in account " + c.DestinationAccount + ", which this connector's role cannot query"
		}
		if u.Reason != "" {
			unread = append(unread, u)
			continue
		}
		arn := c.LogGroupIdentifier()
		g := byARN[arn]
		if g == nil {
			g = &dnsLogGroup{ARN: arn}
			byARN[arn] = g
			order = append(order, arn)
		}
		g.VPCs = dnsAppendUnique(g.VPCs, vpcs...)
		g.Configs = dnsAppendUnique(g.Configs, c.ID)
	}
	sort.Strings(order)
	out := make([]dnsLogGroup, 0, len(order))
	for _, arn := range order {
		g := byARN[arn]
		sort.Strings(g.VPCs)
		out = append(out, *g)
	}
	return out, unread
}

func unreadDNSCoverage(unread []dnsUnread) models.SurfaceCoverage {
	parts := make([]string, 0, len(unread))
	for _, u := range unread {
		parts = append(parts, fmt.Sprintf("%s (VPCs %s) -> %s: %s", u.Config, strings.Join(u.VPCs, ", "), u.Destination, u.Reason))
	}
	return models.SurfaceCoverage{State: models.CloudCoverageUnsupported, Count: len(unread),
		Error: "query logs not read, so lookups in these VPCs are not seen: " + strings.Join(parts, "; ")}
}

// dnsCoverage is the region's read as coverage: reached when every log group
// was read whole; partial when some were not (failed, truncated, lapsed, or
// above the per-scan cap); the failure's own state when none could be read.
func dnsCoverage(reads []dnsLogGroupRead, skipped []dnsLogGroup, writeErr error) models.SurfaceCoverage {
	if writeErr != nil {
		return models.SurfaceCoverage{State: models.CloudCoverageDenied,
			Error: "recording DNS evidence: " + writeErr.Error()}
	}
	var failed []dnsLogGroupRead
	var notes []string
	read := 0
	for _, r := range reads {
		switch {
		case r.Err != nil:
			failed = append(failed, r)
		default:
			read++
			if r.Read.Truncated {
				notes = append(notes, fmt.Sprintf("%s: the query reached its %d-row limit, some groups may be missing", r.Group.ARN, awsdiscovery.DNSResultLimit))
			}
			if r.Read.Window.Lapsed {
				notes = append(notes, fmt.Sprintf("%s: last read %s, only the last %s were read", r.Group.ARN,
					r.Read.Window.Since.Format(time.RFC3339), awsdiscovery.DNSMaxReadWindow))
			}
		}
	}
	if len(skipped) > 0 {
		names := make([]string, 0, len(skipped))
		for _, g := range skipped {
			names = append(names, g.ARN)
		}
		notes = append(notes, fmt.Sprintf("%d log group(s) above the per-scan cap of %d not read: %s",
			len(skipped), dnsMaxLogGroupsPerRegion, strings.Join(names, ", ")))
	}
	if len(failed) > 0 && read == 0 && len(skipped) == 0 {
		cov := surfaceResult(0, failed[0].Err)
		cov.Error = fmt.Sprintf("%d of %d log groups could not be read: %s", len(failed), len(reads), cov.Error)
		return cov
	}
	if len(failed) == 0 && len(notes) == 0 {
		return models.SurfaceCoverage{State: models.CloudCoverageReached, Count: read}
	}
	cov := models.SurfaceCoverage{State: models.CloudCoveragePartial, Count: read}
	for _, f := range failed {
		notes = append([]string{f.Group.ARN + ": " + f.Err.Error()}, notes...)
	}
	if len(failed) > 0 {
		first := surfaceResult(0, failed[len(failed)-1].Err)
		cov.API, cov.ErrorCode = first.API, first.ErrorCode
	}
	cov.Error = fmt.Sprintf("%d of %d log groups read whole; ", read-dnsPartialReads(reads), len(reads)+len(skipped)) + strings.Join(notes, "; ")
	return cov
}

func dnsPartialReads(reads []dnsLogGroupRead) int {
	n := 0
	for _, r := range reads {
		if r.Err == nil && r.Read.Partial() {
			n++
		}
	}
	return n
}

// withDNSTemplateNote adds, to a refused DNS read, the fact about the
// connector's template: the version that first grants the reads, and the one
// its stack reports. A fact, not a diagnosis (an SCP refuses the same call).
func withDNSTemplateNote(cov models.SurfaceCoverage, recorded string) models.SurfaceCoverage {
	if cov.State != models.CloudCoverageDenied || !strings.HasPrefix(cov.ErrorCode, "AccessDenied") {
		return cov
	}
	if recorded != "" && recorded >= awsdiscovery.DNSQueryLogTemplateVersion {
		return cov
	}
	stack := "reports no template version"
	if recorded != "" {
		stack = "reports " + recorded
	}
	cov.Error += fmt.Sprintf("; discovery template %s is the first to grant the DNS query-log reads, and this connector's stack %s",
		awsdiscovery.DNSQueryLogTemplateVersion, stack)
	return cov
}

/* --------------------------------- attribution ------------------------------ */

// dnsSourceKey is one source of lookups.
type dnsSourceKey struct{ VPC, Addr string }

// dnsSourceAttr is what was found about a source address at scan time.
type dnsSourceAttr struct {
	ENI     *awsdiscovery.ENIInfo
	ECSTask *awsdiscovery.ECSTaskRef
	// Err is why the lookup failed ("" when it did not).
	Err string
}

// resolveDNSSources looks up the interface holding every source address, per
// VPC, and the task of every ECS task interface. A failed lookup leaves its
// sources unattributed (to their VPC) and is a warning.
func resolveDNSSources(ctx context.Context, clients DNSClients, reads []dnsLogGroupRead,
	warn func(string, ...any)) map[dnsSourceKey]dnsSourceAttr {
	byVPC := map[string]map[string]bool{}
	for _, r := range reads {
		for _, a := range r.Read.Aggregates {
			if a.SrcAddr == "" {
				continue
			}
			if byVPC[a.VPCID] == nil {
				byVPC[a.VPCID] = map[string]bool{}
			}
			byVPC[a.VPCID][a.SrcAddr] = true
		}
	}
	out := map[dnsSourceKey]dnsSourceAttr{}
	reader := awsdiscovery.NewDNSAttributionReader(clients.ENI, clients.ECS)
	vpcs := make([]string, 0, len(byVPC))
	for v := range byVPC {
		vpcs = append(vpcs, v)
	}
	sort.Strings(vpcs)
	var ecsENIs []string
	for _, vpc := range vpcs {
		ips := sortedKeys(byVPC[vpc])
		enis, err := reader.NetworkInterfaces(ctx, vpc, ips)
		if err != nil {
			warn("resolving source addresses in %s: %v", vpc, err)
			for _, ip := range ips {
				out[dnsSourceKey{vpc, ip}] = dnsSourceAttr{Err: dnsCallFailure("ec2:DescribeNetworkInterfaces", err)}
			}
			continue
		}
		for _, ip := range ips {
			e, ok := enis[ip]
			if !ok {
				continue
			}
			out[dnsSourceKey{vpc, ip}] = dnsSourceAttr{ENI: &e}
			if e.Kind == awsdiscovery.ENIKindECSTask {
				ecsENIs = append(ecsENIs, e.ID)
			}
		}
	}
	if len(ecsENIs) > 0 {
		tasks, err := reader.ECSTasksByENI(ctx, ecsENIs)
		if err != nil {
			warn("resolving ECS task interfaces: %v", err)
		}
		for k, a := range out {
			if a.ENI == nil || a.ENI.Kind != awsdiscovery.ENIKindECSTask {
				continue
			}
			if t, ok := tasks[a.ENI.ID]; ok {
				a.ECSTask = &t
			} else if err != nil {
				a.Err = dnsCallFailure("ecs:DescribeTasks", err)
			}
			out[k] = a
		}
	}
	return out
}

// dnsCallFailure is a short, stable failure label: the call and AWS's code.
func dnsCallFailure(call string, err error) string {
	if c := awsdiscovery.CallName(err); c != "" {
		call = c
	}
	return call + " " + awsdiscovery.ErrorCode(err)
}

// dnsWorkload is one inventory workload a source can be attributed to.
type dnsWorkload struct {
	ID          uuid.UUID
	RuntimeKind string
	NativeID    string
	Name        string
	Region      string
	IdentityID  *uuid.UUID
	IdentityARN string
}

type dnsInventory struct {
	byNative map[string]*dnsWorkload // runtime_kind \x1f native_id
	lambdas  []*dnsWorkload          // longest name first
}

func (inv dnsInventory) find(kind, native string) *dnsWorkload {
	return inv.byNative[kind+"\x1f"+native]
}

// lambdaFor matches the function named by a Lambda interface's description:
// the longest inventory name that is the hint or a "<name>-" prefix of it.
func (inv dnsInventory) lambdaFor(hint string) *dnsWorkload {
	if hint == "" {
		return nil
	}
	for _, w := range inv.lambdas {
		if hint == w.Name || strings.HasPrefix(hint, w.Name+"-") {
			return w
		}
	}
	return nil
}

func loadDNSInventory(tx *gorm.DB, ws, connectorID uuid.UUID, region string) (dnsInventory, error) {
	var rows []dnsWorkload
	if err := tx.Raw(`SELECT w.id, w.runtime_kind, w.native_id, w.name, w.region, w.identity_id,
	                         COALESCE(i.native_id, '') AS identity_arn
	                    FROM cloud_workload w
	                    LEFT JOIN cloud_identity i ON i.id = w.identity_id AND i.workspace_id = w.workspace_id
	                   WHERE w.workspace_id = ? AND w.connector_id = ? AND w.region = ?
	                     AND w.runtime_kind IN (?, ?, ?)`,
		ws, connectorID, region, models.WorkloadLambdaFunction, models.WorkloadECSTaskDefinition,
		models.WorkloadEC2Instance).Scan(&rows).Error; err != nil {
		return dnsInventory{}, fmt.Errorf("read workloads: %w", err)
	}
	inv := dnsInventory{byNative: map[string]*dnsWorkload{}}
	for i := range rows {
		w := &rows[i]
		inv.byNative[w.RuntimeKind+"\x1f"+w.NativeID] = w
		if w.RuntimeKind == models.WorkloadLambdaFunction && w.Name != "" {
			inv.lambdas = append(inv.lambdas, w)
		}
	}
	sort.SliceStable(inv.lambdas, func(i, j int) bool { return len(inv.lambdas[i].Name) > len(inv.lambdas[j].Name) })
	return inv, nil
}

// dnsSubject is who a group of lookups is attributed to.
type dnsSubject struct {
	Key         string
	IdentityID  *uuid.UUID
	Subject     map[string]any
	Attribution dnsAttribution
}

// attributeDNSLookups decides a source's subject. In order: a Lambda
// interface (the function it names), an ECS task interface (its task
// definition), an instance (srcids.instance, recorded at lookup time, else
// the interface's attachment), else the VPC.
func attributeDNSLookups(a awsdiscovery.DNSLookupAggregate, attr dnsSourceAttr, inv dnsInventory,
	region, account, partition string) dnsSubject {
	e := attr.ENI
	if e != nil && e.Kind == awsdiscovery.ENIKindLambda {
		if w := inv.lambdaFor(e.LambdaFunctionHint); w != nil {
			return workloadDNSSubject(w, dnsAttribution{How: "eni_lambda", Confidence: "scan_time",
				Note: "Lambda shares one network interface across the functions with the same subnets and security groups; the interface names the function that created it"})
		}
		if e.LambdaFunctionHint != "" {
			if partition == "" {
				partition = "aws"
			}
			arn := e.LambdaFunctionHint
			if account != "" {
				arn = fmt.Sprintf("arn:%s:lambda:%s:%s:function:%s", partition, region, account, e.LambdaFunctionHint)
			}
			return uninventoriedDNSSubject(models.WorkloadLambdaFunction, arn, e.LambdaFunctionHint, region,
				dnsAttribution{How: "eni_lambda", Confidence: "scan_time",
					Note: "the function named by the Lambda network interface is not in this connector's inventory"})
		}
	}
	if e != nil && e.Kind == awsdiscovery.ENIKindECSTask && attr.ECSTask != nil && attr.ECSTask.TaskDefinitionARN != "" {
		how := dnsAttribution{How: "eni_ecs_task", Confidence: "scan_time", Note: "task " + attr.ECSTask.TaskARN}
		if w := inv.find(models.WorkloadECSTaskDefinition, attr.ECSTask.TaskDefinitionARN); w != nil {
			return workloadDNSSubject(w, how)
		}
		return uninventoriedDNSSubject(models.WorkloadECSTaskDefinition, attr.ECSTask.TaskDefinitionARN,
			"", region, how)
	}
	instance, how := a.InstanceID, dnsAttribution{How: "srcids_instance", Confidence: "query_time"}
	if instance == "" && e != nil && e.InstanceID != "" {
		instance, how = e.InstanceID, dnsAttribution{How: "eni_instance", Confidence: "scan_time"}
	}
	if instance != "" && (e == nil || e.Kind != awsdiscovery.ENIKindECSTask) {
		if e != nil && (e.Kind == awsdiscovery.ENIKindEKSPod || (e.InstanceID == instance && !e.PrimaryIP)) {
			how.PodLevel = "unresolved"
			how.Note = "the address is a secondary address of the instance's network interfaces (on an EKS node, a pod's); the pod is not resolved"
		}
		if w := inv.find(models.WorkloadEC2Instance, instance); w != nil {
			return workloadDNSSubject(w, how)
		}
		return uninventoriedDNSSubject(models.WorkloadEC2Instance, instance, "", region, how)
	}
	vpc := a.VPCID
	if vpc == "" {
		vpc = "unknown"
	}
	how = dnsAttribution{How: "unattributed", Confidence: "none",
		Note: "model traffic from an unknown source in VPC " + vpc}
	if attr.Err != "" {
		how.Note += " (lookup failed: " + attr.Err + ")"
	} else if e != nil && e.Kind == awsdiscovery.ENIKindECSTask {
		how.Note += " (an ECS task network interface whose running task was not found)"
	} else if e == nil {
		how.Note += " (no network interface holds the address now)"
	}
	return dnsSubject{Key: "vpc:" + region + ":" + vpc, Attribution: how,
		Subject: map[string]any{"kind": "vpc", "vpc_id": vpc, "region": region, "account": account}}
}

func workloadDNSSubject(w *dnsWorkload, how dnsAttribution) dnsSubject {
	subj := map[string]any{"kind": "workload", "in_inventory": true, "cloud_workload_id": w.ID,
		"runtime_kind": w.RuntimeKind, "native_id": w.NativeID, "name": w.Name, "region": w.Region}
	if w.IdentityID != nil {
		subj["identity_id"] = *w.IdentityID
		subj["identity_arn"] = w.IdentityARN
	}
	if how.PodLevel != "" {
		subj["pod_level"] = how.PodLevel
	}
	return dnsSubject{Key: dnsWorkloadKey(w.RuntimeKind, w.Region, w.NativeID), IdentityID: w.IdentityID,
		Subject: subj, Attribution: how}
}

func uninventoriedDNSSubject(kind, native, name, region string, how dnsAttribution) dnsSubject {
	subj := map[string]any{"kind": "workload", "in_inventory": false, "runtime_kind": kind,
		"native_id": native, "name": name, "region": region}
	if how.PodLevel != "" {
		subj["pod_level"] = how.PodLevel
	}
	return dnsSubject{Key: dnsWorkloadKey(kind, region, native), Subject: subj, Attribution: how}
}

func dnsWorkloadKey(kind, region, native string) string {
	return "workload:" + kind + ":" + region + ":" + native
}

/* ----------------------------------- evidence ------------------------------- */

type dnsDomainCount struct {
	Domain    string    `json:"domain"`
	Provider  string    `json:"provider"`
	Control   bool      `json:"control,omitempty"`
	Queries   int64     `json:"queries"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type dnsSourceRef struct {
	SrcAddr    string    `json:"srcaddr"`
	InstanceID string    `json:"instance_id,omitempty"`
	VPCID      string    `json:"vpc_id"`
	ENIID      string    `json:"eni_id,omitempty"`
	ENIKind    string    `json:"eni_kind,omitempty"`
	ENIType    string    `json:"eni_interface_type,omitempty"`
	Queries    int64     `json:"queries"`
	LastSeen   time.Time `json:"last_seen"`
}

type dnsLogGroupRef struct {
	ARN    string   `json:"arn"`
	Region string   `json:"region"`
	VPCs   []string `json:"vpcs"`
}

type dnsAttribution struct {
	How        string `json:"how"`
	Confidence string `json:"confidence"`
	Note       string `json:"note,omitempty"`
	PodLevel   string `json:"pod_level,omitempty"`
}

// dnsTrafficDoc is an ai_network_traffic finding's evidence: model hosts
// only, never another domain.
type dnsTrafficDoc struct {
	Source           string           `json:"source"`
	Providers        []string         `json:"providers"`
	ControlOnly      bool             `json:"control_only"`
	Queries          int64            `json:"queries"`
	FirstSeen        time.Time        `json:"first_seen"`
	LastSeen         time.Time        `json:"last_seen"`
	Domains          []dnsDomainCount `json:"domains"`
	Sources          []dnsSourceRef   `json:"sources"`
	SourcesTruncated bool             `json:"sources_truncated,omitempty"`
	LogGroups        []dnsLogGroupRef `json:"log_groups"`
	Attribution      dnsAttribution   `json:"attribution"`
	// Partial: a window this evidence came from was not read whole.
	Partial     bool     `json:"partial"`
	Limitations []string `json:"limitations"`
}

// add folds one aggregate in.
func (d *dnsTrafficDoc) add(a awsdiscovery.DNSLookupAggregate, attr dnsSourceAttr) {
	d.Queries += a.Queries
	if !a.FirstSeen.IsZero() && (d.FirstSeen.IsZero() || a.FirstSeen.Before(d.FirstSeen)) {
		d.FirstSeen = a.FirstSeen
	}
	if a.LastSeen.After(d.LastSeen) {
		d.LastSeen = a.LastSeen
	}
	found := false
	for i := range d.Domains {
		c := &d.Domains[i]
		if c.Domain != a.Domain {
			continue
		}
		found = true
		c.Queries += a.Queries
		if !a.FirstSeen.IsZero() && (c.FirstSeen.IsZero() || a.FirstSeen.Before(c.FirstSeen)) {
			c.FirstSeen = a.FirstSeen
		}
		if a.LastSeen.After(c.LastSeen) {
			c.LastSeen = a.LastSeen
		}
	}
	if !found {
		d.Domains = append(d.Domains, dnsDomainCount{Domain: a.Domain, Provider: a.Provider, Control: a.Control,
			Queries: a.Queries, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen})
	}
	ref := dnsSourceRef{SrcAddr: a.SrcAddr, InstanceID: a.InstanceID, VPCID: a.VPCID, Queries: a.Queries, LastSeen: a.LastSeen}
	if attr.ENI != nil {
		ref.ENIID, ref.ENIKind, ref.ENIType = attr.ENI.ID, attr.ENI.Kind, attr.ENI.InterfaceType
	}
	for i := range d.Sources {
		s := &d.Sources[i]
		if s.SrcAddr == ref.SrcAddr && s.InstanceID == ref.InstanceID && s.VPCID == ref.VPCID {
			s.Queries += ref.Queries
			if ref.LastSeen.After(s.LastSeen) {
				s.LastSeen = ref.LastSeen
			}
			if ref.ENIID != "" {
				s.ENIID, s.ENIKind, s.ENIType = ref.ENIID, ref.ENIKind, ref.ENIType
			}
			return
		}
	}
	if len(d.Sources) >= dnsMaxSourcesPerFinding {
		d.SourcesTruncated = true
		return
	}
	d.Sources = append(d.Sources, ref)
}

// merge folds this scan's delta into the stored doc. Windows never overlap
// (each starts at the previous read_to), so counts add.
func (d dnsTrafficDoc) merge(delta *dnsTrafficDoc) dnsTrafficDoc {
	for _, c := range delta.Domains {
		merged := false
		for i := range d.Domains {
			t := &d.Domains[i]
			if t.Domain != c.Domain {
				continue
			}
			t.Queries += c.Queries
			t.FirstSeen = earlierTime(t.FirstSeen, c.FirstSeen)
			if c.LastSeen.After(t.LastSeen) {
				t.LastSeen = c.LastSeen
			}
			merged = true
		}
		if !merged {
			d.Domains = append(d.Domains, c)
		}
	}
	d.Queries += delta.Queries
	d.FirstSeen = earlierTime(d.FirstSeen, delta.FirstSeen)
	if delta.LastSeen.After(d.LastSeen) {
		d.LastSeen = delta.LastSeen
	}
	// Sources: by (srcaddr, instance, vpc), queries summed.
	for _, s := range delta.Sources {
		merged := false
		for i := range d.Sources {
			t := &d.Sources[i]
			if t.SrcAddr == s.SrcAddr && t.InstanceID == s.InstanceID && t.VPCID == s.VPCID {
				t.Queries += s.Queries
				if s.LastSeen.After(t.LastSeen) {
					t.LastSeen = s.LastSeen
				}
				if s.ENIID != "" {
					t.ENIID, t.ENIKind, t.ENIType = s.ENIID, s.ENIKind, s.ENIType
				}
				merged = true
				break
			}
		}
		if !merged {
			if len(d.Sources) >= dnsMaxSourcesPerFinding {
				d.SourcesTruncated = true
			} else {
				d.Sources = append(d.Sources, s)
			}
		}
	}
	d.SourcesTruncated = d.SourcesTruncated || delta.SourcesTruncated
	for _, g := range delta.LogGroups {
		d.LogGroups = mergeDNSLogGroup(d.LogGroups, g)
	}
	d.Partial = d.Partial || delta.Partial
	d.Attribution = delta.Attribution
	d.finish()
	return d
}

// earlierTime is the earlier of two times, a zero time counting as unknown.
func earlierTime(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func mergeDNSLogGroup(groups []dnsLogGroupRef, g dnsLogGroupRef) []dnsLogGroupRef {
	for i := range groups {
		if groups[i].ARN == g.ARN {
			groups[i].VPCs = dnsAppendUnique(groups[i].VPCs, g.VPCs...)
			sort.Strings(groups[i].VPCs)
			return groups
		}
	}
	return append(groups, g)
}

// finish recomputes the derived fields and sorts for a stable document.
func (d *dnsTrafficDoc) finish() {
	d.Source = dnsEvidenceSource
	d.Limitations = dnsLimitations
	providers := map[string]bool{}
	control := true
	for _, c := range d.Domains {
		providers[c.Provider] = true
		control = control && c.Control
	}
	d.Providers = sortedKeys(providers)
	d.ControlOnly = control && len(d.Domains) > 0
	sort.Slice(d.Domains, func(i, j int) bool { return d.Domains[i].Domain < d.Domains[j].Domain })
	sort.Slice(d.Sources, func(i, j int) bool {
		a, b := d.Sources[i], d.Sources[j]
		if a.VPCID != b.VPCID {
			return a.VPCID < b.VPCID
		}
		if a.SrcAddr != b.SrcAddr {
			return a.SrcAddr < b.SrcAddr
		}
		return a.InstanceID < b.InstanceID
	})
	sort.Slice(d.LogGroups, func(i, j int) bool { return d.LogGroups[i].ARN < d.LogGroups[j].ARN })
	if d.Domains == nil {
		d.Domains = []dnsDomainCount{}
	}
	if d.Sources == nil {
		d.Sources = []dnsSourceRef{}
	}
}

func dnsAppendUnique(s []string, vs ...string) []string {
	for _, v := range vs {
		dup := false
		for _, x := range s {
			if x == v {
				dup = true
				break
			}
		}
		if !dup && v != "" {
			s = append(s, v)
		}
	}
	return s
}

/* ------------------------------------ the store ----------------------------- */

// errDNSCursorMoved: a cursor is not where this read started; the whole write
// is refused rather than counting a window twice.
var errDNSCursorMoved = errors.New("dns cursor moved since it was read")

// dnsCursor is one stored mark.
type dnsCursor struct {
	LogGroupARN string
	ReadTo      time.Time
	CoveredFrom time.Time
	LastError   string
}

// dnsEvidenceStore lands DNS findings and cursors, in one transaction under
// row-level security for the workspace and, when the scan has one, its fence.
type dnsEvidenceStore struct {
	db    *gorm.DB
	fence *repositories.ScanFence
}

// Cursors reads one region's marks by log group.
func (st dnsEvidenceStore) Cursors(ctx context.Context, ws, connectorID uuid.UUID, region string) (map[string]dnsCursor, error) {
	var rows []dnsCursor
	err := tenancy.InWorkspaceRead(ctx, st.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT log_group_arn, read_to, covered_from, last_error FROM cloud_dns_cursor
		                WHERE workspace_id = ? AND connector_id = ? AND region = ? AND stream = 'dns'`,
			ws, connectorID, region).Scan(&rows).Error
	})
	out := map[string]dnsCursor{}
	for _, r := range rows {
		r.ReadTo, r.CoveredFrom = r.ReadTo.UTC(), r.CoveredFrom.UTC()
		out[r.LogGroupARN] = r
	}
	return out, err
}

// dnsWrite is one region's DNS evidence to land.
type dnsWrite struct {
	WorkspaceID, ConnectorID uuid.UUID
	Region, Account          string
	Partition                string
	Reads                    []dnsLogGroupRead
	Sources                  map[dnsSourceKey]dnsSourceAttr
	Now                      time.Time
}

// dnsWriteResult counts what a write did.
type dnsWriteResult struct {
	Written  int // findings opened or refreshed
	Resolved int
}

// dnsDraft is one subject's lookups this scan.
type dnsDraft struct {
	subject dnsSubject
	doc     dnsTrafficDoc
}

// Record lands one region's DNS read: findings opened or refreshed, settled
// cursors moved, failed attempts recorded, quiet findings resolved -- or,
// when any of it fails, nothing.
func (st dnsEvidenceStore) Record(ctx context.Context, w dnsWrite) (dnsWriteResult, error) {
	var res dnsWriteResult
	err := tenancy.InWorkspace(ctx, st.db, w.WorkspaceID, func(tx *gorm.DB) error {
		return repositories.RunFenced(tx, st.fence, func(tx *gorm.DB) error {
			res = dnsWriteResult{}
			// 1. The marks must be the ones the reads began at.
			var stored []dnsCursor
			if err := tx.Raw(`SELECT log_group_arn, read_to, covered_from, last_error FROM cloud_dns_cursor
			                   WHERE workspace_id = ? AND connector_id = ? AND region = ? AND stream = 'dns'
			                   FOR UPDATE`, w.WorkspaceID, w.ConnectorID, w.Region).Scan(&stored).Error; err != nil {
				return err
			}
			cursors := map[string]dnsCursor{}
			for _, c := range stored {
				c.ReadTo, c.CoveredFrom = c.ReadTo.UTC(), c.CoveredFrom.UTC()
				cursors[c.LogGroupARN] = c
			}
			for _, r := range w.Reads {
				if r.Err == nil && !r.Skipped && !cursors[r.Group.ARN].ReadTo.Equal(r.Read.Window.Since) {
					return fmt.Errorf("%w: %s: stored %s, read from %s", errDNSCursorMoved, r.Group.ARN,
						cursors[r.Group.ARN].ReadTo.Format(time.RFC3339), r.Read.Window.Since.Format(time.RFC3339))
				}
			}

			// 2. This scan's lookups, by subject.
			inv, err := loadDNSInventory(tx, w.WorkspaceID, w.ConnectorID, w.Region)
			if err != nil {
				return err
			}
			drafts := map[string]*dnsDraft{}
			for _, r := range w.Reads {
				if r.Err != nil || r.Skipped {
					continue
				}
				for _, a := range r.Read.Aggregates {
					attr := w.Sources[dnsSourceKey{a.VPCID, a.SrcAddr}]
					subj := attributeDNSLookups(a, attr, inv, w.Region, w.Account, w.Partition)
					d := drafts[subj.Key]
					if d == nil {
						d = &dnsDraft{subject: subj}
						drafts[subj.Key] = d
					}
					d.doc.add(a, attr)
					d.doc.LogGroups = mergeDNSLogGroup(d.doc.LogGroups,
						dnsLogGroupRef{ARN: r.Group.ARN, Region: w.Region, VPCs: append([]string(nil), r.Group.VPCs...)})
					d.doc.Partial = d.doc.Partial || r.Read.Partial()
					d.doc.Attribution = subj.Attribution
				}
			}

			// 3. Open or refresh each subject's finding.
			keys := make([]string, 0, len(drafts))
			for k := range drafts {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := upsertDNSFinding(tx, w, drafts[k]); err != nil {
					return err
				}
				res.Written++
			}

			// 4. Move the settled cursors; record failed attempts.
			for _, r := range w.Reads {
				if r.Skipped {
					continue
				}
				if r.Err != nil {
					if err := tx.Exec(`UPDATE cloud_dns_cursor
					                      SET last_error = ?, last_attempt_at = ?, updated_at = ?
					                    WHERE workspace_id = ? AND connector_id = ? AND region = ? AND stream = 'dns'
					                      AND log_group_arn = ?`,
						truncateTrailError(r.Err.Error()), w.Now, w.Now,
						w.WorkspaceID, w.ConnectorID, w.Region, r.Group.ARN).Error; err != nil {
						return err
					}
					c := cursors[r.Group.ARN]
					c.LastError = r.Err.Error()
					cursors[r.Group.ARN] = c
					continue
				}
				win := r.Read.Window
				prev, had := cursors[r.Group.ARN]
				covered := win.From
				if had && !win.Lapsed && win.From.Equal(prev.ReadTo) {
					covered = prev.CoveredFrom
				}
				if r.Read.Truncated {
					covered = win.To
				}
				var reasons []string
				if r.Read.Truncated {
					reasons = append(reasons, "truncated")
				}
				if win.Lapsed {
					reasons = append(reasons, "lapsed")
				}
				if err := tx.Exec(`INSERT INTO cloud_dns_cursor
				                      (workspace_id, connector_id, region, stream, log_group_arn, window_from, covered_from,
				                       read_to, partial, partial_reason, records_scanned, bytes_scanned, groups,
				                       last_error, last_attempt_at, updated_at)
				                   VALUES (?, ?, ?, 'dns', ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
				                   ON CONFLICT (workspace_id, connector_id, region, stream, log_group_arn) DO UPDATE
				                      SET window_from = EXCLUDED.window_from, covered_from = EXCLUDED.covered_from,
				                          read_to = EXCLUDED.read_to, partial = EXCLUDED.partial,
				                          partial_reason = EXCLUDED.partial_reason,
				                          records_scanned = EXCLUDED.records_scanned, bytes_scanned = EXCLUDED.bytes_scanned,
				                          groups = EXCLUDED.groups, last_error = '',
				                          last_attempt_at = EXCLUDED.last_attempt_at, updated_at = EXCLUDED.updated_at`,
					w.WorkspaceID, w.ConnectorID, w.Region, r.Group.ARN, win.From, covered, win.To,
					r.Read.Partial(), strings.Join(reasons, ","), int64(r.Read.RecordsScanned), int64(r.Read.BytesScanned),
					len(r.Read.Aggregates), w.Now, w.Now).Error; err != nil {
					return err
				}
				cursors[r.Group.ARN] = dnsCursor{LogGroupARN: r.Group.ARN, ReadTo: win.To, CoveredFrom: covered}
			}

			// 5. Resolve the region's findings quiet for 30 days, read without
			// a gap since their last lookup.
			n, err := resolveQuietDNSFindings(tx, w, cursors)
			if err != nil {
				return err
			}
			res.Resolved = n
			return nil
		})
	})
	if err != nil {
		return dnsWriteResult{}, err
	}
	return res, nil
}

// upsertDNSFinding merges a subject's lookups into its finding (reopening a
// resolved one).
func upsertDNSFinding(tx *gorm.DB, w dnsWrite, d *dnsDraft) error {
	var prev []struct {
		Evidence []byte
	}
	if err := tx.Raw(`SELECT evidence FROM agent_finding
	                   WHERE workspace_id = ? AND kind = ? AND subject_key = ? FOR UPDATE`,
		w.WorkspaceID, FindingAINetworkTraffic, d.subject.Key).Scan(&prev).Error; err != nil {
		return fmt.Errorf("read finding: %w", err)
	}
	var doc dnsTrafficDoc
	if len(prev) == 1 && len(prev[0].Evidence) > 0 {
		if err := json.Unmarshal(prev[0].Evidence, &doc); err != nil || doc.Source != dnsEvidenceSource {
			doc = dnsTrafficDoc{} // unreadable: rebuilt from here
		}
	}
	d.doc.finish()
	doc = doc.merge(&d.doc)
	subj, err := json.Marshal(d.subject.Subject)
	if err != nil {
		return err
	}
	ev, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	first, last := doc.FirstSeen, doc.LastSeen
	if first.IsZero() {
		first = w.Now
	}
	if last.IsZero() {
		last = first
	}
	if err := tx.Exec(`INSERT INTO agent_finding
		  (workspace_id, connector_id, kind, subject_key, identity_id, subject, evidence, state,
		   first_seen, last_seen, resolved_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, 'open', ?, ?, NULL, ?, ?)
		ON CONFLICT (workspace_id, kind, subject_key) DO UPDATE SET
		  connector_id = excluded.connector_id, identity_id = excluded.identity_id,
		  subject = excluded.subject, evidence = excluded.evidence, state = 'open',
		  first_seen = excluded.first_seen, last_seen = excluded.last_seen,
		  resolved_at = NULL, updated_at = excluded.updated_at`,
		w.WorkspaceID, w.ConnectorID, FindingAINetworkTraffic, d.subject.Key, d.subject.IdentityID,
		string(subj), string(ev), first, last, w.Now, w.Now).Error; err != nil {
		return fmt.Errorf("upsert finding %s: %w", d.subject.Key, err)
	}
	return nil
}

// resolveQuietDNSFindings resolves the connector's open ai_network_traffic
// findings in this region whose last lookup is 30 days old and whose every log
// group has been read since then without a gap and without a failure. A log
// group no longer read keeps its findings open: unknown is not "no traffic".
func resolveQuietDNSFindings(tx *gorm.DB, w dnsWrite, cursors map[string]dnsCursor) (int, error) {
	var open []struct {
		ID       uuid.UUID
		LastSeen time.Time
		Evidence []byte
	}
	if err := tx.Raw(`SELECT id, last_seen, evidence FROM agent_finding
	                   WHERE workspace_id = ? AND connector_id = ? AND kind = ? AND state = 'open'
	                     AND subject->>'region' = ?`,
		w.WorkspaceID, w.ConnectorID, FindingAINetworkTraffic, w.Region).Scan(&open).Error; err != nil {
		return 0, fmt.Errorf("read open DNS findings: %w", err)
	}
	resolved := 0
	for _, f := range open {
		last := f.LastSeen.UTC()
		if w.Now.Sub(last) < DNSTrafficResolveAfter {
			continue
		}
		var doc dnsTrafficDoc
		if err := json.Unmarshal(f.Evidence, &doc); err != nil || len(doc.LogGroups) == 0 {
			continue
		}
		quiet := true
		for _, g := range doc.LogGroups {
			c, ok := cursors[g.ARN]
			if !ok || c.LastError != "" || c.CoveredFrom.After(last) || c.ReadTo.Before(last.Add(DNSTrafficResolveAfter)) {
				quiet = false
				break
			}
		}
		if !quiet {
			continue
		}
		r := tx.Exec(`UPDATE agent_finding SET state = 'resolved', resolved_at = ?, updated_at = ?
		               WHERE workspace_id = ? AND id = ? AND state = 'open'`, w.Now, w.Now, w.WorkspaceID, f.ID)
		if r.Error != nil {
			return resolved, fmt.Errorf("resolve DNS finding: %w", r.Error)
		}
		resolved += int(r.RowsAffected)
	}
	return resolved, nil
}
