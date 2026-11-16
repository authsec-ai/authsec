package services

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	apikeys "google.golang.org/api/apikeys/v2"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	storage "google.golang.org/api/storage/v1"
)

/* cloud_gcp_scan_credentials.go holds GCP-2's three non-service-account
   surfaces: HMAC keys, API keys and workload identity federation config.

   NEVER KEY MATERIAL. An HMAC key's secret is returned by Google once, at
   creation, and list/get never carry it. An API key's string comes only from the
   separate getKeyString method, which nothing here calls. A V2Key does have a
   KeyString field in the generated type; no line in this file reads it, and the
   shared schema has no column that would accept it. This is the code-side half
   of that promise, and the integration test plants a secret in the fake to prove
   it never reaches the database.

   EACH SURFACE HAS ITS OWN ACCUMULATOR. A denial on one never marks another not
   reached.

   A SURFACE THE PROBE SAYS IS UNREADABLE IS NOT ATTEMPTED. It is recorded as
   not_selected with a "not_readable:" reason -- the state Complete() already
   treats as "not attempted, by design" -- and the reconcile skips its kinds
   rather than deleting what an earlier, readable scan found. */

const gcpCredentialsTimeout = 15 * time.Minute

const (
	gcpHMACPageSize   = 250
	gcpAPIKeysPageSz  = 300
	gcpPoolPageSize   = 100
	gcpProviderPageSz = 100
)

// gcpProvider is one workload identity federation provider as read from Google.
// Kept in the scan snapshot only (GCP-4 joins it to principal:// members); never
// persisted. JWKS and SAML metadata bodies are deliberately not carried.
type gcpProvider struct {
	ProjectID string
	// ProjectRef is the project segment of the provider's own resource name.
	// Google names it by NUMBER, which a project-scoped connector otherwise never
	// learns; binding members name pools by number too, so this is the join key.
	ProjectRef string
	Pool      string
	Provider  string
	// Type is aws | oidc | saml | x509 | unknown.
	Type               string
	IssuerURI          string
	AllowedAudiences   []string
	AWSAccount         string
	AttributeMapping   map[string]string
	AttributeCondition string
	State              string
	Disabled           bool
}

// gcpCredentialAccs are the three surfaces this file owns.
type gcpCredentialAccs struct {
	hmac       *gcpSurfaceAcc
	apiKeys    *gcpSurfaceAcc
	federation *gcpSurfaceAcc
}

func newGCPCredentialAccs() gcpCredentialAccs {
	return gcpCredentialAccs{
		hmac:       newGCPSurfaceAcc(),
		apiKeys:    newGCPSurfaceAcc(),
		federation: newGCPSurfaceAcc(),
	}
}

// gcpCollectorPermissions is what each GCP-2 collector actually CALLS. It is a
// subset of the probe's per-surface list on purpose: the probe asks for list AND
// get (so it can say whether a surface is fully usable), but these collectors
// only ever call list. Gating on the probe's own `can` would skip a surface the
// reader can read just because it lacks a get it never uses -- which is exactly
// what happened live: the reader held every .list and none of the .get.
var gcpCollectorPermissions = map[string][]string{
	gcp.SurfaceHMACKeys: {"storage.hmacKeys.list"},
	gcp.SurfaceAPIKeys:  {"apikeys.keys.list"},
	gcp.SurfaceFederationConfig: {
		"iam.workloadIdentityPools.list",
		"iam.workloadIdentityPoolProviders.list",
	},
	// GCP-3. The probe lists searchAllResources for resource_iam, which is not
	// what the binding collector calls; both binding surfaces ride one
	// searchAllIamPolicies read.
	gcp.SurfaceAllowBindings: {"cloudasset.assets.searchAllIamPolicies"},
	gcp.SurfaceResourceIAM:   {"cloudasset.assets.searchAllIamPolicies"},
	// Custom roles are listed, predefined ones fetched with roles.get.
	gcp.SurfaceRoles: {"iam.roles.list", "iam.roles.get"},
}

// gcpProbeSaysUnreadable reports whether the last permission probe PROVED the
// reader lacks a permission this surface's collector calls. Unknown or
// never-probed is not "unreadable": the surface is attempted, and a real refusal
// is then an honest denial. A permission the probe asked about but the collector
// does not use (the .get half) never skips the surface.
func gcpProbeSaysUnreadable(attrs models.GCPConnectorAttrs, surface string) (string, bool) {
	c, ok := attrs.CapabilityProfile[surface]
	if !ok || c.Unknown || c.Can {
		return "", false
	}
	needed := gcpCollectorPermissions[surface]
	var missing []string
	for _, m := range c.Missing {
		for _, n := range needed {
			if m == n {
				missing = append(missing, m)
			}
		}
	}
	if len(needed) > 0 && len(missing) == 0 {
		return "", false // only a permission this collector never calls is missing
	}
	sort.Strings(missing)
	if len(missing) == 0 {
		return "not_readable", true
	}
	return "not_readable: missing " + strings.Join(missing, ", "), true
}

// skipNotReadable records a surface that was deliberately not attempted.
func (a *gcpSurfaceAcc) skipNotReadable(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.skipped = true
	a.state = models.CloudCoverageNotSelected
	a.reason = reason
}

// runCredentialPhases reads HMAC keys, API keys and federation config, each
// under its own deadline derived from the scan-wide context.
func (s *GCPScanner) runCredentialPhases(
	scanCtx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	attrs models.GCPConnectorAttrs, authOpt option.ClientOption, iamClient *iam.Service,
	governor *gcp.Governor, accs gcpCredentialAccs, written []gcpWrittenIdentity,
) {
	// HMAC keys
	if reason, skip := gcpProbeSaysUnreadable(attrs, gcp.SurfaceHMACKeys); skip {
		accs.hmac.skipNotReadable(reason)
	} else if client, err := s.newStorageClient(scanCtx, authOpt); err != nil {
		accs.hmac.fail(err)
	} else {
		ctx, cancel := context.WithTimeout(scanCtx, gcpCredentialsTimeout)
		s.collectHMACKeys(ctx, workspaceID, snapshot, client, governor, accs.hmac, written)
		cancel()
	}

	// API keys
	if reason, skip := gcpProbeSaysUnreadable(attrs, gcp.SurfaceAPIKeys); skip {
		accs.apiKeys.skipNotReadable(reason)
	} else if client, err := s.newAPIKeysClient(scanCtx, authOpt); err != nil {
		accs.apiKeys.fail(err)
	} else {
		ctx, cancel := context.WithTimeout(scanCtx, gcpCredentialsTimeout)
		s.collectAPIKeys(ctx, workspaceID, snapshot, client, governor, accs.apiKeys, written)
		cancel()
	}

	// Federation config (snapshot only; nothing is written to the database).
	if reason, skip := gcpProbeSaysUnreadable(attrs, gcp.SurfaceFederationConfig); skip {
		accs.federation.skipNotReadable(reason)
	} else {
		ctx, cancel := context.WithTimeout(scanCtx, gcpCredentialsTimeout)
		snapshot.Providers = s.collectFederation(ctx, snapshot, iamClient, governor, accs.federation)
		cancel()
	}
}

// forEachProject runs work for every project under the governor's concurrency
// cap, the same shape as collectIdentities. work records its own outcome on acc.
func forEachProject(
	ctx context.Context, projects []gcpProject, governor *gcp.Governor,
	acc *gcpSurfaceAcc, work func(gcpProject),
) {
	var wg sync.WaitGroup
	for _, project := range projects {
		if err := ctx.Err(); err != nil {
			acc.observe(err, 0)
			break
		}
		release, err := governor.AcquireProject(ctx)
		if err != nil {
			acc.observe(err, 0)
			break
		}
		wg.Add(1)
		go func(p gcpProject, release func()) {
			defer wg.Done()
			defer release()
			work(p)
		}(project, release)
	}
	wg.Wait()
}

/* -------------------------------- HMAC keys --------------------------------- */

func (s *GCPScanner) collectHMACKeys(
	ctx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	client *storage.Service, governor *gcp.Governor, acc *gcpSurfaceAcc,
	written []gcpWrittenIdentity,
) {
	if len(snapshot.Projects) == 0 {
		acc.observeVacuous()
		return
	}
	forEachProject(ctx, snapshot.Projects, governor, acc, func(project gcpProject) {
		keys, err := s.listHMACKeys(ctx, client, governor, project)
		if err != nil {
			if gcp.IsScopeInsufficient(err) {
				// The token's read-only scopes cannot cover hmacKeys.list, whatever
				// roles the reader holds (live-confirmed). Not a denial a role
				// fixes: report the surface as not readable, never as denied.
				acc.skipNotReadable("not_readable: token scopes cannot list HMAC keys")
				return
			}
			if gcp.IsServiceDisabled(err) {
				// Cloud Storage is not enabled here, so there are no HMAC keys to
				// find: reached, zero. Not a denial -- see gcp.IsServiceDisabled.
				acc.observe(nil, 0)
				return
			}
			acc.observe(err, 0)
			return
		}
		count := 0
		var writeErr error
		for _, k := range keys {
			if err := s.upsertHMACKey(workspaceID, snapshot, project, k, written); err != nil {
				writeErr = err
				break
			}
			count++
		}
		acc.observe(writeErr, count)
	})
}

func (s *GCPScanner) listHMACKeys(
	ctx context.Context, client *storage.Service, governor *gcp.Governor, project gcpProject,
) ([]*storage.HmacKeyMetadata, error) {
	var (
		out       []*storage.HmacKeyMetadata
		pageToken string
	)
	for page := 0; page < gcpMaxPages; page++ {
		var resp *storage.HmacKeysMetadata
		token := pageToken
		if err := gcp.Retry(ctx, func() error {
			if err := governor.Storage.Wait(ctx); err != nil {
				return err
			}
			r, callErr := client.Projects.HmacKeys.List(project.ProjectID).
				MaxResults(gcpHMACPageSize).PageToken(token).Context(ctx).Do()
			if callErr != nil {
				return callErr
			}
			resp = r
			return nil
		}); err != nil {
			return nil, err
		}
		out = append(out, resp.Items...)
		if resp.NextPageToken == "" {
			return out, nil
		}
		pageToken = resp.NextPageToken
	}
	return nil, errTooManyGCPPages
}

// gcpHMACKeyNativeID is namespaced: uq_cloud_secret_native is workspace-wide and
// shared with AWS access keys and Azure credentials.
func gcpHMACKeyNativeID(accessID string) string {
	return "//storage.googleapis.com/hmacKeys/" + accessID
}

func (s *GCPScanner) upsertHMACKey(
	workspaceID uuid.UUID, snapshot *GCPScanSnapshot, project gcpProject,
	k *storage.HmacKeyMetadata, written []gcpWrittenIdentity,
) error {
	if k.AccessId == "" {
		return fmt.Errorf("gcp: hmac key in project %s has no accessId", project.ProjectID)
	}
	if k.ServiceAccountEmail == "" {
		return fmt.Errorf("gcp: hmac key %s has no service account", k.AccessId)
	}

	// An HMAC key belongs to a service account. Resolve it to the real row; a
	// service account this scan did not read (another project) becomes a member
	// row, the same path a binding would take.
	m, err := gcp.ParseMember("serviceAccount:" + k.ServiceAccountEmail)
	if err != nil {
		return err
	}
	owner, err := s.upsertMemberIdentity(workspaceID, snapshot, m, written)
	if err != nil {
		return err
	}

	secret := &models.CloudSecret{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		IdentityID:         owner.IdentityID,
		Kind:               models.CloudSecretGCPHMACKey,
		NativeID:           gcpHMACKeyNativeID(k.AccessId),
		ProviderCreatedAt:  parseGCPTime(k.TimeCreated),
		ExpiresAt:          nil, // an HMAC key has no expiry
		LastUsedAt:         nil, // UNKNOWN until Policy Analyzer / audit logs
		Status:             gcpHMACStatus(k.State),
		LastSeenGeneration: snapshot.Generation,
	}
	if err := secret.SetGCPAttrs(models.GCPSecretAttrs{
		ServiceAccountEmail: k.ServiceAccountEmail,
		ProjectID:           firstNonEmpty(k.ProjectId, project.ProjectID),
		ProjectNumber:       project.Number,
		HMACState:           k.State,
	}); err != nil {
		return err
	}
	_, _, err = s.identities.UpsertSecret(secret)
	return err
}

func gcpHMACStatus(state string) string {
	if strings.EqualFold(state, "ACTIVE") {
		return models.CloudSecretActive
	}
	return models.CloudSecretInactive
}

/* --------------------------------- API keys --------------------------------- */

func (s *GCPScanner) collectAPIKeys(
	ctx context.Context, workspaceID uuid.UUID, snapshot *GCPScanSnapshot,
	client *apikeys.Service, governor *gcp.Governor, acc *gcpSurfaceAcc,
	written []gcpWrittenIdentity,
) {
	if len(snapshot.Projects) == 0 {
		acc.observeVacuous()
		return
	}
	forEachProject(ctx, snapshot.Projects, governor, acc, func(project gcpProject) {
		keys, err := s.listAPIKeys(ctx, client, governor, project)
		if err != nil {
			if gcp.IsServiceDisabled(err) {
				// The API Keys API is not enabled on this project: nothing is
				// managed through it. Reached, zero.
				acc.observe(nil, 0)
				return
			}
			acc.observe(err, 0)
			return
		}
		count := 0
		var writeErr error
		for _, k := range keys {
			if err := s.upsertAPIKey(workspaceID, snapshot, project, k, written); err != nil {
				writeErr = err
				break
			}
			count++
		}
		acc.observe(writeErr, count)
	})
}

func (s *GCPScanner) listAPIKeys(
	ctx context.Context, client *apikeys.Service, governor *gcp.Governor, project gcpProject,
) ([]*apikeys.V2Key, error) {
	var (
		out       []*apikeys.V2Key
		pageToken string
	)
	parent := "projects/" + project.ProjectID + "/locations/global"
	for page := 0; page < gcpMaxPages; page++ {
		var resp *apikeys.V2ListKeysResponse
		token := pageToken
		if err := gcp.Retry(ctx, func() error {
			if err := governor.APIKeys.Wait(ctx); err != nil {
				return err
			}
			// keys.list returns metadata and restrictions. It does not return the
			// key string; getKeyString is the only call that does and is never made.
			r, callErr := client.Projects.Locations.Keys.List(parent).
				PageSize(gcpAPIKeysPageSz).PageToken(token).Context(ctx).Do()
			if callErr != nil {
				return callErr
			}
			resp = r
			return nil
		}); err != nil {
			return nil, err
		}
		out = append(out, resp.Keys...)
		if resp.NextPageToken == "" {
			return out, nil
		}
		pageToken = resp.NextPageToken
	}
	return nil, errTooManyGCPPages
}

// gcpAPIKeyNativeID is namespaced; the resource name carries the project number
// and key uid, so it is unique across projects.
func gcpAPIKeyNativeID(name string) string { return "//apikeys.googleapis.com/" + name }

// gcpProjectNativeID is the owner row of a project-owned credential.
func gcpProjectNativeID(number string) string {
	return "//cloudresourcemanager.googleapis.com/projects/" + number
}

// gcpProjectNumberFromKeyName reads the immutable project number out of
// "projects/<number>/locations/global/keys/<uid>".
func gcpProjectNumberFromKeyName(name string) string {
	rest := strings.TrimPrefix(name, "projects/")
	if rest == name {
		return ""
	}
	num, _, _ := strings.Cut(rest, "/")
	return num
}

func (s *GCPScanner) upsertAPIKey(
	workspaceID uuid.UUID, snapshot *GCPScanSnapshot, project gcpProject,
	k *apikeys.V2Key, written []gcpWrittenIdentity,
) error {
	if k.Name == "" || k.Uid == "" {
		return fmt.Errorf("gcp: api key in project %s has no name or uid", project.ProjectID)
	}
	number := firstNonEmpty(gcpProjectNumberFromKeyName(k.Name), project.Number)

	// Owner. A key bound to a service account hangs off that account; otherwise
	// it belongs to the project, which needs a row because cloud_secret.identity_id
	// is NOT NULL and shared with AWS and Azure.
	var ownerID uuid.UUID
	if k.ServiceAccountEmail != "" {
		m, err := gcp.ParseMember("serviceAccount:" + k.ServiceAccountEmail)
		if err != nil {
			return err
		}
		o, err := s.upsertMemberIdentity(workspaceID, snapshot, m, written)
		if err != nil {
			return err
		}
		ownerID = o.IdentityID
	} else {
		if number == "" {
			return fmt.Errorf("gcp: api key %s: project number unknown", k.Uid)
		}
		o, err := s.upsertProjectIdentity(workspaceID, snapshot, project, number)
		if err != nil {
			return err
		}
		ownerID = o
	}

	secret := &models.CloudSecret{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		IdentityID:         ownerID,
		Kind:               models.CloudSecretGCPAPIKey,
		NativeID:           gcpAPIKeyNativeID(k.Name),
		ProviderCreatedAt:  parseGCPTime(k.CreateTime),
		ExpiresAt:          nil,
		LastUsedAt:         nil,
		Status:             gcpAPIKeyStatus(k),
		LastSeenGeneration: snapshot.Generation,
	}
	if err := secret.SetGCPAttrs(models.GCPSecretAttrs{
		DisplayName:         k.DisplayName,
		ProjectID:           project.ProjectID,
		ProjectNumber:       number,
		ServiceAccountEmail: k.ServiceAccountEmail,
		Restrictions:        gcpAPIKeyRestrictions(k.Restrictions),
	}); err != nil {
		return err
	}
	_, _, err := s.identities.UpsertSecret(secret)
	return err
}

func (s *GCPScanner) upsertProjectIdentity(
	workspaceID uuid.UUID, snapshot *GCPScanSnapshot, project gcpProject, number string,
) (uuid.UUID, error) {
	identity := &models.CloudIdentity{
		WorkspaceID:        workspaceID,
		ConnectorID:        snapshot.ConnectorID,
		Kind:               models.CloudIdentityGCPProject,
		NativeID:           gcpProjectNativeID(number),
		Name:               project.ProjectID,
		Enabled:            true,
		LastSeenGeneration: snapshot.Generation,
	}
	if err := identity.SetGCPAttrs(models.GCPIdentityAttrs{
		ProjectID: project.ProjectID, ProjectNumber: number, IdentityKind: "project",
	}); err != nil {
		return uuid.Nil, err
	}
	stored, _, err := s.identities.UpsertIdentity(identity)
	if err != nil {
		return uuid.Nil, err
	}
	return stored.ID, nil
}

func gcpAPIKeyStatus(k *apikeys.V2Key) string {
	if k.DeleteTime != "" {
		return models.CloudSecretInactive
	}
	return models.CloudSecretActive
}

// gcpAPIKeyRestrictions summarises what a key is limited to. Unrestricted is the
// finding that matters: a key that any caller anywhere can use.
func gcpAPIKeyRestrictions(r *apikeys.V2Restrictions) *models.GCPAPIKeyRestrictions {
	out := &models.GCPAPIKeyRestrictions{}
	if r != nil {
		for _, t := range r.ApiTargets {
			if t != nil && t.Service != "" {
				out.APITargets = append(out.APITargets, t.Service)
			}
		}
		if r.BrowserKeyRestrictions != nil {
			out.Referrers = append(out.Referrers, r.BrowserKeyRestrictions.AllowedReferrers...)
		}
		if r.ServerKeyRestrictions != nil {
			out.IPs = append(out.IPs, r.ServerKeyRestrictions.AllowedIps...)
		}
		if r.AndroidKeyRestrictions != nil {
			for _, a := range r.AndroidKeyRestrictions.AllowedApplications {
				if a != nil && a.PackageName != "" {
					out.Android = append(out.Android, a.PackageName)
				}
			}
		}
		if r.IosKeyRestrictions != nil {
			out.IOS = append(out.IOS, r.IosKeyRestrictions.AllowedBundleIds...)
		}
	}
	out.Unrestricted = len(out.APITargets)+len(out.Referrers)+len(out.IPs)+len(out.Android)+len(out.IOS) == 0
	return out
}

/* ------------------------- federation (snapshot only) ----------------------- */

func (s *GCPScanner) collectFederation(
	ctx context.Context, snapshot *GCPScanSnapshot, client *iam.Service,
	governor *gcp.Governor, acc *gcpSurfaceAcc,
) []gcpProvider {
	if len(snapshot.Projects) == 0 {
		acc.observeVacuous()
		return nil
	}
	var (
		mu  sync.Mutex
		out []gcpProvider
	)
	forEachProject(ctx, snapshot.Projects, governor, acc, func(project gcpProject) {
		providers, err := s.listProjectProviders(ctx, client, governor, project)
		if err != nil {
			if gcp.IsServiceDisabled(err) {
				acc.observe(nil, 0)
				return
			}
			acc.observe(err, 0)
			return
		}
		mu.Lock()
		out = append(out, providers...)
		mu.Unlock()
		acc.observe(nil, len(providers))
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProjectID != out[j].ProjectID {
			return out[i].ProjectID < out[j].ProjectID
		}
		if out[i].Pool != out[j].Pool {
			return out[i].Pool < out[j].Pool
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

func (s *GCPScanner) listProjectProviders(
	ctx context.Context, client *iam.Service, governor *gcp.Governor, project gcpProject,
) ([]gcpProvider, error) {
	parent := "projects/" + project.ProjectID + "/locations/global"
	var (
		pools     []*iam.WorkloadIdentityPool
		pageToken string
	)
	for page := 0; ; page++ {
		if page >= gcpMaxPages {
			return nil, errTooManyGCPPages
		}
		var resp *iam.ListWorkloadIdentityPoolsResponse
		token := pageToken
		if err := gcp.Retry(ctx, func() error {
			if err := governor.IAM.Wait(ctx); err != nil {
				return err
			}
			r, callErr := client.Projects.Locations.WorkloadIdentityPools.List(parent).
				PageSize(gcpPoolPageSize).PageToken(token).Context(ctx).Do()
			if callErr != nil {
				return callErr
			}
			resp = r
			return nil
		}); err != nil {
			return nil, err
		}
		pools = append(pools, resp.WorkloadIdentityPools...)
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	var out []gcpProvider
	for _, pool := range pools {
		poolID := lastSegment(pool.Name)
		if poolID == "" || gcp.IsAuthSecPool(poolID) {
			continue // AuthSec's own onboarding pool is not a customer finding
		}
		provs, err := s.listPoolProviders(ctx, client, governor, pool.Name)
		if err != nil {
			return nil, err
		}
		for _, p := range provs {
			out = append(out, gcpProviderFrom(project, poolID, p))
		}
	}
	return out, nil
}

func (s *GCPScanner) listPoolProviders(
	ctx context.Context, client *iam.Service, governor *gcp.Governor, poolName string,
) ([]*iam.WorkloadIdentityPoolProvider, error) {
	var (
		out       []*iam.WorkloadIdentityPoolProvider
		pageToken string
	)
	for page := 0; page < gcpMaxPages; page++ {
		var resp *iam.ListWorkloadIdentityPoolProvidersResponse
		token := pageToken
		if err := gcp.Retry(ctx, func() error {
			if err := governor.IAM.Wait(ctx); err != nil {
				return err
			}
			r, callErr := client.Projects.Locations.WorkloadIdentityPools.Providers.List(poolName).
				PageSize(gcpProviderPageSz).PageToken(token).Context(ctx).Do()
			if callErr != nil {
				return callErr
			}
			resp = r
			return nil
		}); err != nil {
			return nil, err
		}
		out = append(out, resp.WorkloadIdentityPoolProviders...)
		if resp.NextPageToken == "" {
			return out, nil
		}
		pageToken = resp.NextPageToken
	}
	return nil, errTooManyGCPPages
}

func gcpProviderFrom(project gcpProject, poolID string, p *iam.WorkloadIdentityPoolProvider) gcpProvider {
	out := gcpProvider{
		ProjectID:          project.ProjectID,
		ProjectRef:         gcp.PoolProject(p.Name),
		Pool:               poolID,
		Provider:           lastSegment(p.Name),
		Type:               "unknown",
		AttributeMapping:   p.AttributeMapping,
		AttributeCondition: p.AttributeCondition,
		State:              p.State,
		Disabled:           p.Disabled,
	}
	switch {
	case p.Aws != nil:
		out.Type, out.AWSAccount = "aws", p.Aws.AccountId
	case p.Oidc != nil:
		out.Type, out.IssuerURI, out.AllowedAudiences = "oidc", p.Oidc.IssuerUri, p.Oidc.AllowedAudiences
	case p.Saml != nil:
		out.Type = "saml"
	case p.X509 != nil:
		out.Type = "x509"
	}
	return out
}

func lastSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}
