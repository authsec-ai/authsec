package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Resource-policy collection (SPEC-iga-phase3-policy.md §3.9, T3.03b): the
// per-scan, immutable evidence the first-attachment proof and the route
// analysis (§3.4) read. It runs inside the existing scan, under the pipeline
// barrier, when the IGA_POLICY gate is available (AWSScanWorker.execute), and
// writes 056: per (form, region) one cloud_resource_policy_coverage row, per
// resource read one cloud_resource_policy_observation (including "no
// policy"), and each document once in cloud_policy_document under the
// sha256 of its RFC 8785 text (igagov.CanonicalDocument -- the same hash the
// insert trigger recomputes).
//
// The S3/KMS summary in cloud_aws_permission_scan.go (scanResourcePolicies,
// surface resource_policies) is unchanged and stays for the graph's evidence
// panel; the compiler never reads it, and this never feeds it.

// ReasonTemplateUpdateNeeded is the not_collected reason of a connector whose
// recorded discovery template predates collection (§3.9).
const ReasonTemplateUpdateNeeded = "discovery template update needed"

// resourcePolicyBudget bounds one scan's collection (§3.9 "Budget"): a form
// that cannot finish within it is partial, never silently complete.
// DECISION (T3.03b-8): 30 minutes, inside the scan's lease (renewed by the
// heartbeat) and well below the barrier's recovery horizon.
const resourcePolicyBudget = 30 * time.Minute

// ResourcePolicyCollection reports what one scan recorded.
type ResourcePolicyCollection struct {
	ScanRunID uuid.UUID
	// TemplateCurrent is false when the connector's recorded template does
	// not grant collection: every form was recorded not_collected unread.
	TemplateCurrent bool
	// EnabledRegionsKnown is false when the account's enabled regions could
	// not be listed (unselected regions then have no rows; the compiler's
	// enabled-region list still names them, as not_collected).
	EnabledRegionsKnown bool
	Coverage            []awsdiscovery.FormCoverage
	// Regions is the region scope this collection used, frozen with the run
	// (models.ScanCoverage.Regions): the scan worker stamps it on the run's
	// coverage at publication.
	Regions models.ScanRegionScope
	// FormsWritten counts the (form, region) units this attempt wrote;
	// FormsAlreadyRecorded the units an earlier attempt of the same run had.
	FormsWritten, FormsAlreadyRecorded   int
	Observations, Documents, Unparseable int
	// WriteErrors names each unit whose write failed. The unit then has no
	// rows at all, which every reader takes as not collected.
	WriteErrors []string
}

// WithResourcePolicyClients installs per-region collection clients,
// bypassing assume-role. A test seam.
func (s *AWSPermissionScanner) WithResourcePolicyClients(f awsdiscovery.ResourcePolicyClientsFunc) *AWSPermissionScanner {
	s.rpClients = f
	return s
}

// WithRegionsAPI installs the ec2:DescribeRegions client used to find the
// enabled-but-unselected regions, bypassing assume-role. A test seam.
func (s *AWSPermissionScanner) WithRegionsAPI(api awsdiscovery.RegionsAPI) *AWSPermissionScanner {
	s.regionsAPI = api
	return s
}

// WithCollectorOptions overrides the collection's pacing, retries and budget.
func (s *AWSPermissionScanner) WithCollectorOptions(o awsdiscovery.CollectorOptions) *AWSPermissionScanner {
	s.collectorOpts = &o
	return s
}

// CollectResourcePolicies collects and records §3.9's evidence for one scan
// run of one connector. Every AWS failure is a coverage fact, never an
// error; the error return is for a connector that cannot be read at all. A
// unit whose write fails is reported in WriteErrors and leaves no rows.
func (s *AWSPermissionScanner) CollectResourcePolicies(
	ctx context.Context, workspaceID, connectorID, scanRunID uuid.UUID,
) (*ResourcePolicyCollection, error) {
	connector, err := s.onboardingConnector(workspaceID, connectorID)
	if err != nil {
		return nil, err
	}
	attrs := connector.AWSAttrs()
	partition := attrs.Partition
	if partition == "" {
		partition = awsdiscovery.PartitionOf(attrs.RoleARN)
	}
	out := &ResourcePolicyCollection{ScanRunID: scanRunID,
		Regions: models.ScanRegionScope{Selected: sortedRegionNames(attrs.Regions), Enabled: []string{}}}

	if !awsdiscovery.GrantsResourcePolicyCollection(attrs.TemplateVersion) {
		// §3.9: "Connectors on the older template record every collected form
		// as not_collected ('discovery template update needed')" -- nothing is
		// called, so the older stack never produces an error (DECISION
		// T3.03b-5 reads an unrecorded version as older).
		reason := fmt.Sprintf("%s: template %q predates %s", ReasonTemplateUpdateNeeded,
			attrs.TemplateVersion, awsdiscovery.ResourcePolicyTemplateVersion)
		out.Coverage = awsdiscovery.NotCollectedAll(partition, attrs.Regions, reason)
	} else {
		out.TemplateCurrent = true
		enabled, known := s.enabledRegions(ctx, workspaceID, connectorID, attrs.Regions)
		out.EnabledRegionsKnown = known
		if known {
			out.Regions.Enabled, out.Regions.EnabledKnown = sortedRegionNames(enabled), true
		}
		opts := awsdiscovery.CollectorOptions{}
		if s.collectorOpts != nil {
			opts = *s.collectorOpts
		}
		if opts.Deadline.IsZero() {
			now := time.Now
			if opts.Now != nil {
				now = opts.Now
			}
			opts.Deadline = now().Add(resourcePolicyBudget)
		}
		out.Coverage = awsdiscovery.NewResourcePolicyCollector(opts).Collect(ctx, awsdiscovery.CollectInput{
			AccountID: connector.ScopeID, Partition: partition,
			SelectedRegions: attrs.Regions, EnabledRegions: enabled,
			Clients: s.resourcePolicyClientsFor(workspaceID, connectorID),
		})
	}

	for i := range out.Coverage {
		cov := &out.Coverage[i]
		row, docs, obs, unparseable := evidenceRows(workspaceID, connectorID, scanRunID, cov)
		wrote, werr := s.rpRepo.RecordForm(row, docs, obs)
		if werr != nil {
			if errors.Is(werr, repositories.ErrScanFenceLost) {
				return out, werr // superseded: stop, write nothing more
			}
			out.WriteErrors = append(out.WriteErrors, fmt.Sprintf("%s/%s: %v", cov.Form, cov.Region, werr))
			log.Printf("resource-policy collection: run=%s %s/%s: %v", scanRunID, cov.Form, cov.Region, werr)
			continue
		}
		if !wrote {
			out.FormsAlreadyRecorded++
			continue
		}
		out.FormsWritten++
		out.Observations += len(obs)
		out.Documents += len(docs)
		out.Unparseable += unparseable
	}
	return out, nil
}

// evidenceRows turns one collected (form, region) into 056 rows. A policy
// text is stored by its RFC 8785 canonical form and content hash. Text that
// is valid JSON but not an IAM policy igagov can decode is stored the same
// way, parse_state unparseable. Text that is not I-JSON at all (a duplicate
// member name, invalid UTF-8 escapes ...) has no canonical JSON form; it is
// stored as a JSON STRING holding the text exactly as AWS returned it,
// parse_state unparseable (DECISION T3.03b-9): the observation still records
// that a policy exists and keeps its bytes for review, and the compiler's
// route analysis reports it not_analysed (policy_unparseable). Only text no
// jsonb can hold (U+0000, invalid UTF-8) cannot be stored; that read is
// counted failed, so the coverage cannot be complete.
func evidenceRows(ws, conn, scan uuid.UUID, cov *awsdiscovery.FormCoverage) (
	*models.CloudResourcePolicyCoverage, []models.CloudPolicyDocument, []models.CloudResourcePolicyObservation, int,
) {
	docs := map[string]models.CloudPolicyDocument{}
	var obs []models.CloudResourcePolicyObservation
	unparseable, unstorable := 0, 0
	for _, rd := range cov.Reads {
		o := models.CloudResourcePolicyObservation{
			WorkspaceID: ws, ScanRunID: scan, ResourceForm: cov.Form, Region: cov.Region,
			ResourceARN: rd.ARN, PolicyPresent: rd.Present, ParseState: igagov.ParseParsed, ReadAt: rd.ReadAt,
		}
		if o.ReadAt.IsZero() {
			o.ReadAt = time.Now().UTC()
		}
		if rd.Present {
			canonical, hash, parsed, ok := storableDocument(rd.Text)
			if !ok {
				unstorable++
				continue
			}
			docs[hash] = models.CloudPolicyDocument{WorkspaceID: ws, DocumentHash: hash,
				Canonical: string(canonical), Document: canonical}
			h := hash
			o.DocumentHash = &h
			if !parsed {
				o.ParseState = igagov.ParseUnparseable
				unparseable++
			}
		}
		obs = append(obs, o)
	}
	if unstorable > 0 {
		cov.ReadOK -= unstorable
		cov.ReadFailed += unstorable
		note := fmt.Sprintf("%d policy document(s) could not be stored (not representable as jsonb)", unstorable)
		if cov.State == awsdiscovery.CoverageComplete {
			cov.State, cov.Reason = awsdiscovery.CoveragePartial, note
		} else {
			cov.Reason = strings.TrimSpace(cov.Reason + "; " + note)
		}
	}
	row := &models.CloudResourcePolicyCoverage{
		WorkspaceID: ws, ConnectorID: conn, ScanRunID: scan, ResourceForm: cov.Form, Region: cov.Region,
		State: cov.State, Enumerated: cov.Enumerated, ReadOK: cov.ReadOK, ReadFailed: cov.ReadFailed,
		Reason: cov.Reason,
	}
	list := make([]models.CloudPolicyDocument, 0, len(docs))
	for _, d := range docs {
		list = append(list, d)
	}
	return row, list, obs, unparseable
}

// storableDocument returns the canonical text and content hash a policy text
// is stored under, and whether igagov decodes it as a policy document.
func storableDocument(text string) (canonical []byte, hash string, parsed, ok bool) {
	if c, h, err := igagov.CanonicalDocument(text); err == nil {
		_, perr := igagov.DecodePolicyDocument(text)
		return c, h, perr == nil, true
	}
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return nil, "", false, false
	}
	c, err := igagov.CanonicalizeValue(text)
	if err != nil || strings.Contains(string(c), `\u0000`) {
		return nil, "", false, false
	}
	return c, igagov.ContentHash(c), false, true
}

// enabledRegions lists the account's enabled regions, for the unselected
// ones' not_collected rows. A failure is logged and leaves them unknown:
// the compiler's own enabled-region list then names them as not_collected
// (igagov.AnalyzeRoutes treats a missing row exactly so).
func (s *AWSPermissionScanner) enabledRegions(ctx context.Context, ws, conn uuid.UUID, selected []string) ([]string, bool) {
	api := s.regionsAPI
	if api == nil {
		if s.rpClients != nil || s.onboarding == nil {
			return nil, false // injected collection clients and no regions double: unknown
		}
		cfg, _, err := s.onboarding.ConfigForConnector(ctx, ws, conn, awsdiscovery.SigningRegion(selected))
		if err != nil {
			log.Printf("resource-policy collection: regions for %s: %v", conn, err)
			return nil, false
		}
		api = awsdiscovery.NewRegionsClient(cfg)
	}
	regions, err := awsdiscovery.EnabledRegions(ctx, api)
	if err != nil {
		log.Printf("resource-policy collection: enabled regions for %s: %v", conn, err)
		return nil, false
	}
	names := make([]string, 0, len(regions))
	for _, r := range regions {
		names = append(names, r.Name)
	}
	return names, true
}

// sortedRegionNames is a sorted, de-duplicated copy without empty names.
func sortedRegionNames(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range in {
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// resourcePolicyClientsFor returns the per-region client source: an injected
// one wins (tests); otherwise real clients from the connector's assumed-role
// config for that region.
func (s *AWSPermissionScanner) resourcePolicyClientsFor(ws, conn uuid.UUID) awsdiscovery.ResourcePolicyClientsFunc {
	if s.rpClients != nil {
		return s.rpClients
	}
	return func(ctx context.Context, region string) (awsdiscovery.ResourcePolicyClients, error) {
		if s.onboarding == nil {
			return awsdiscovery.ResourcePolicyClients{}, errors.New("no onboarding service to assume a role with")
		}
		cfg, _, err := s.onboarding.ConfigForConnector(ctx, ws, conn, region)
		if err != nil {
			return awsdiscovery.ResourcePolicyClients{}, err
		}
		return awsdiscovery.NewResourcePolicyClients(cfg), nil
	}
}

// LoadResourcePolicyEvidence is what the compiler and the evidence bundle
// builder read (§3.9 "Which evidence a plan used"): exactly one scan's
// coverage and observations -- the run named for the role's partition in the
// manifest of the revision being compiled, never "current" rows -- with each
// parsed observation's document decoded from its stored canonical text. nil
// when the scan recorded no coverage at all (igagov.AnalyzeRoutes then
// reports no_resource_policy_coverage).
func LoadResourcePolicyEvidence(db *gorm.DB, workspaceID, scanRunID uuid.UUID) (*igagov.ResourcePolicyEvidence, error) {
	repo := repositories.NewCloudResourcePolicyRepository(db)
	cov, err := repo.CoverageForScan(workspaceID, scanRunID)
	if err != nil {
		return nil, fmt.Errorf("read resource-policy coverage: %w", err)
	}
	if len(cov) == 0 {
		return nil, nil
	}
	obs, err := repo.ObservationsForScan(workspaceID, scanRunID)
	if err != nil {
		return nil, fmt.Errorf("read resource-policy observations: %w", err)
	}
	var hashes []string
	for _, o := range obs {
		if o.DocumentHash != nil && o.ParseState == igagov.ParseParsed {
			hashes = append(hashes, *o.DocumentHash)
		}
	}
	docs, err := repo.Documents(workspaceID, hashes)
	if err != nil {
		return nil, fmt.Errorf("read resource-policy documents: %w", err)
	}
	ev := &igagov.ResourcePolicyEvidence{}
	for _, c := range cov {
		ev.Coverage = append(ev.Coverage, igagov.CoverageRow{Form: c.ResourceForm, Region: c.Region, State: c.State, Reason: c.Reason})
	}
	for _, o := range obs {
		ro := igagov.ResourcePolicyObservation{Form: o.ResourceForm, Region: o.Region, ResourceARN: o.ResourceARN,
			PolicyPresent: o.PolicyPresent, ParseState: o.ParseState}
		if o.DocumentHash != nil {
			ro.DocumentHash = *o.DocumentHash
			if d, ok := docs[ro.DocumentHash]; ok && o.ParseState == igagov.ParseParsed {
				if pd, derr := igagov.DecodePolicyDocument(d.Canonical); derr == nil {
					ro.Document = &pd
				}
				// A stored parsed document that no longer decodes leaves
				// Document nil: AnalyzeRoutes reports it not_analysed, never
				// as a policy granting nothing.
			}
		}
		ev.Observations = append(ev.Observations, ro)
	}
	return ev, nil
}

// PruneResourcePolicyEvidence is the prune_evidence job's resource-policy
// half (§3.9 "Retention"), with the workspace's evidence_retention_revs
// (055; default 30 when the workspace has no settings row). T3.08 schedules
// it daily.
func PruneResourcePolicyEvidence(db *gorm.DB, workspaceID uuid.UUID) (repositories.PruneEvidenceResult, error) {
	settings, err := repositories.NewIGAGovSettingsRepository(db).Get(workspaceID)
	if err != nil {
		return repositories.PruneEvidenceResult{}, fmt.Errorf("read retention setting: %w", err)
	}
	return repositories.NewCloudResourcePolicyRepository(db).PruneEvidence(workspaceID, settings.EvidenceRetentionRevs)
}
