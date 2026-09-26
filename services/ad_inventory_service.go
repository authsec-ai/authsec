package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/directory"
	"github.com/authsec-ai/authsec/internal/directory/adldap"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const adNormalizerVersion = "ad-inventory/1"

// ADReader is the directory the inventory run calls. *adldap.LDAPReader
// implements it; tests substitute a fake.
type ADReader interface {
	DirectoryIdentity(ctx context.Context) (adldap.Identity, error)
	ReadClass(ctx context.Context, baseDN, class string, usnFloor int64, pageSize int) (adldap.ClassRead, error)
}

// ADInventoryService reads administrator-approved AD scopes into the existing
// evidence tables. It does not project iga_identity_accounts.
type ADInventoryService struct {
	DB *gorm.DB
	// NewReader dials the directory. Nil uses adldap.Dial.
	NewReader func(adldap.Conn) (ADReader, error)
	Now       func() time.Time
	// Production is ENVIRONMENT=production. Nil means not production.
	Production func() bool
}

// InventoryConfig is the approved-scope configuration. Password is never part
// of this struct.
type InventoryConfig struct {
	ConfigID       uuid.UUID        `json:"config_id"`
	Server         string           `json:"server,omitempty"`
	Username       string           `json:"username,omitempty"`
	UseSSL         bool             `json:"use_ssl"`
	StartTLS       bool             `json:"start_tls"`
	SkipVerify     bool             `json:"skip_verify"`
	CABundleSet    bool             `json:"ca_bundle_set"`
	CABundle       string           `json:"-"`
	PageSize       int              `json:"page_size"`
	ChangeTracking bool             `json:"change_tracking"`
	TrackingMode   string           `json:"tracking_mode"`
	Scopes         []InventoryScope `json:"scopes"`
}

// InventoryScope is one base DN and the object classes to read inside it.
type InventoryScope struct {
	ID            uuid.UUID `json:"id"`
	BaseDN        string    `json:"base_dn"`
	ObjectClasses []string  `json:"object_classes"`
	Enabled       bool      `json:"enabled"`
}

// InventoryRunView is the API status of one run. It carries no secret material.
type InventoryRunView struct {
	ID          uuid.UUID                 `json:"id"`
	Status      string                    `json:"status"`
	Mode        string                    `json:"mode"`
	ObjectsSeen int                       `json:"objects_seen"`
	ForestID    string                    `json:"forest_id,omitempty"`
	DomainSID   string                    `json:"domain_sid,omitempty"`
	Coverage    []directory.ScopeCoverage `json:"coverage"`
	Error       string                    `json:"error,omitempty"`
	StartedAt   *time.Time                `json:"started_at,omitempty"`
	CompletedAt *time.Time                `json:"completed_at,omitempty"`
}

// ObjectPage is a page of sanitized inventory objects.
type ObjectPage struct {
	Objects    []adldap.Object `json:"objects"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	NextOffset *int            `json:"next_offset,omitempty"`
}

type adConnRow struct {
	ID               uuid.UUID `gorm:"column:id"`
	WorkspaceID      uuid.UUID `gorm:"column:workspace_id"`
	SyncType         string    `gorm:"column:sync_type"`
	IsActive         bool      `gorm:"column:is_active"`
	ADServer         string    `gorm:"column:ad_server"`
	ADUsername       string    `gorm:"column:ad_username"`
	ADPassword       string    `gorm:"column:ad_password"`
	ADBaseDN         string    `gorm:"column:ad_base_dn"`
	ADUseSSL         bool      `gorm:"column:ad_use_ssl"`
	ADSkipVerify     bool      `gorm:"column:ad_skip_verify"`
	ADCABundle       string    `gorm:"column:ad_ca_bundle"`
	ADPageSize       int       `gorm:"column:ad_page_size"`
	ADChangeTracking bool      `gorm:"column:ad_change_tracking"`
	ADStartTLS       bool      `gorm:"column:ad_start_tls"`
	ADTrackingMode   string    `gorm:"column:ad_tracking_mode"`
}

func (adConnRow) TableName() string { return "sync_configurations" }

func (s *ADInventoryService) db() *gorm.DB {
	if s.DB != nil {
		return s.DB
	}
	return nil
}

func (s *ADInventoryService) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *ADInventoryService) production() bool {
	if s.Production != nil {
		return s.Production()
	}
	return false
}

// PutConfig replaces the approved scopes and the additive connection settings
// on an existing AD sync configuration. The bind password is not accepted here;
// it stays in the existing encrypted column.
func (s *ADInventoryService) PutConfig(ctx context.Context, workspaceID uuid.UUID, cfg InventoryConfig) (InventoryConfig, error) {
	db := s.db().WithContext(ctx)
	row, err := s.loadRow(db, workspaceID, cfg.ConfigID)
	if err != nil {
		return InventoryConfig{}, err
	}
	if s.production() && cfg.SkipVerify {
		return InventoryConfig{}, adldap.ErrSkipVerifyRefused
	}
	page := clampADPage(cfg.PageSize)
	mode := strings.ToLower(strings.TrimSpace(cfg.TrackingMode))
	if mode == "" {
		mode = "usn"
	}
	if models.IsDirSyncMode(mode) {
		return InventoryConfig{}, fmt.Errorf("%s", models.DirSyncUnsupportedMessage)
	}
	if mode != "usn" {
		return InventoryConfig{}, fmt.Errorf("tracking_mode must be usn")
	}
	scopes, err := normalizeScopes(cfg.Scopes)
	if err != nil {
		return InventoryConfig{}, err
	}
	updates := map[string]interface{}{
		"ad_page_size":       page,
		"ad_change_tracking": cfg.ChangeTracking,
		"ad_start_tls":       cfg.StartTLS,
		"ad_skip_verify":     cfg.SkipVerify,
		"ad_tracking_mode":   mode,
		"ad_use_ssl":         cfg.UseSSL,
		"updated_at":         s.now(),
	}
	if cfg.Server != "" {
		updates["ad_server"] = cfg.Server
	}
	if cfg.Username != "" {
		updates["ad_username"] = cfg.Username
	}
	if cfg.CABundle != "" || cfg.CABundleSet {
		updates["ad_ca_bundle"] = cfg.CABundle
	}
	if err := db.Model(&adConnRow{}).Where("id = ? AND workspace_id = ?", row.ID, workspaceID).Updates(updates).Error; err != nil {
		return InventoryConfig{}, err
	}
	if err := s.replaceScopes(db, workspaceID, row.ID, scopes); err != nil {
		return InventoryConfig{}, err
	}
	return s.GetConfig(ctx, workspaceID, row.ID)
}

// GetConfig returns the inventory settings. The bind password is not included.
func (s *ADInventoryService) GetConfig(ctx context.Context, workspaceID, configID uuid.UUID) (InventoryConfig, error) {
	db := s.db().WithContext(ctx)
	row, err := s.loadRow(db, workspaceID, configID)
	if err != nil {
		return InventoryConfig{}, err
	}
	scopes, err := s.listScopes(db, workspaceID, configID)
	if err != nil {
		return InventoryConfig{}, err
	}
	mode := row.ADTrackingMode
	if mode == "" {
		mode = "usn"
	}
	out := make([]InventoryScope, 0, len(scopes))
	for _, sc := range scopes {
		out = append(out, InventoryScope{
			ID: sc.ID, BaseDN: sc.BaseDN, ObjectClasses: decodeClasses(sc.ObjectClasses), Enabled: sc.Enabled,
		})
	}
	return InventoryConfig{
		ConfigID: row.ID, Server: row.ADServer, Username: row.ADUsername,
		UseSSL: row.ADUseSSL, StartTLS: row.ADStartTLS, SkipVerify: row.ADSkipVerify,
		CABundleSet: strings.TrimSpace(row.ADCABundle) != "", CABundle: row.ADCABundle,
		PageSize: clampADPage(row.ADPageSize), ChangeTracking: row.ADChangeTracking,
		TrackingMode: mode, Scopes: out,
	}, nil
}

// Run loads the stored connection, decrypts the bind password in memory, and
// executes a scoped inventory read.
func (s *ADInventoryService) Run(ctx context.Context, workspaceID, configID uuid.UUID, requestedBy string) (InventoryRunView, error) {
	db := s.db().WithContext(ctx)
	row, err := s.loadRow(db, workspaceID, configID)
	if err != nil {
		return InventoryRunView{}, err
	}
	if !row.IsActive {
		return InventoryRunView{}, fmt.Errorf("sync configuration is disabled")
	}
	if models.IsDirSyncMode(row.ADTrackingMode) {
		return InventoryRunView{}, fmt.Errorf("%s", models.DirSyncUnsupportedMessage)
	}
	password, err := utils.Decrypt(row.ADPassword)
	if err != nil {
		return InventoryRunView{}, fmt.Errorf("failed to decrypt credentials")
	}
	conn := rowToConn(row, password, s.production())
	scopes, err := s.listScopes(db, workspaceID, configID)
	if err != nil {
		return InventoryRunView{}, err
	}
	if len(enabledScopes(scopes)) == 0 {
		return InventoryRunView{}, fmt.Errorf("no administrator-approved directory scope")
	}
	return s.execute(ctx, workspaceID, row, conn, scopes, requestedBy)
}

func (s *ADInventoryService) execute(ctx context.Context, workspaceID uuid.UUID, row adConnRow, conn adldap.Conn, scopes []models.ADInventoryScope, requestedBy string) (InventoryRunView, error) {
	db := s.db().WithContext(ctx)
	reader, err := s.reader(conn)
	if err != nil {
		return InventoryRunView{}, err
	}
	now := s.now()
	runID := uuid.New()
	adRun := models.ADInventoryRun{
		ID: runID, WorkspaceID: workspaceID, SyncConfigID: row.ID,
		Status: "running", Mode: "full", StartedAt: &now, RequestedBy: requestedBy,
		Coverage: datatypes.JSON("[]"), CreatedAt: now,
	}
	if err := db.Create(&adRun).Error; err != nil {
		return InventoryRunView{}, err
	}
	fail := func(msg string) (InventoryRunView, error) {
		done := s.now()
		_ = db.Model(&models.ADInventoryRun{}).Where("id = ? AND workspace_id = ?", runID, workspaceID).
			Updates(map[string]interface{}{"status": "failed", "error_text": msg, "completed_at": done}).Error
		return InventoryRunView{ID: runID, Status: "failed", Error: msg, StartedAt: &now, CompletedAt: &done}, nil
	}

	ident, err := reader.DirectoryIdentity(ctx)
	if err != nil {
		return fail(err.Error())
	}
	if strings.TrimSpace(ident.ForestID) == "" {
		return fail("rootDSE did not return rootDomainNamingContext")
	}
	integ, err := s.ensureIntegration(db, workspaceID, row, ident, requestedBy)
	if err != nil {
		return fail(err.Error())
	}
	active := enabledScopes(scopes)
	anyIncremental := true
	type classPlan struct {
		scope models.ADInventoryScope
		class string
		mode  string
		floor int64
		iga   uuid.UUID
	}
	var plans []classPlan
	for _, sc := range active {
		igaID, err := s.ensureIGAScope(db, workspaceID, integ.ID, sc)
		if err != nil {
			return fail(err.Error())
		}
		cur, _ := s.loadCursor(db, workspaceID, sc.ID)
		mode, floor := adldap.PlanRead(conn.ChangeTracking, cur, ident.InvocationID)
		if mode != "incremental" {
			anyIncremental = false
		}
		for _, class := range decodeClasses(sc.ObjectClasses) {
			plans = append(plans, classPlan{scope: sc, class: class, mode: mode, floor: floor, iga: igaID})
		}
	}
	runMode := "full"
	if anyIncremental && len(plans) > 0 {
		runMode = "incremental"
	}
	gen, err := s.nextGeneration(db, workspaceID, integ.ID)
	if err != nil {
		return fail(err.Error())
	}
	scan := models.IGAScanRun{
		ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: integ.ID,
		Mode: runMode, Generation: gen, Status: models.ScanRunning,
		RequestedBy: requestedBy, NormalizerVersion: adNormalizerVersion,
		StartedAt: &now, Counters: []byte(`{}`), CreatedAt: now,
	}
	if err := db.Create(&scan).Error; err != nil {
		return fail(err.Error())
	}
	_ = db.Model(&models.ADInventoryRun{}).Where("id = ? AND workspace_id = ?", runID, workspaceID).
		Updates(map[string]interface{}{
			"integration_id": integ.ID, "scan_run_id": scan.ID, "mode": runMode,
		}).Error

	var coverage []directory.ScopeCoverage
	var snapshot directory.ADInventorySnapshot
	snapshot.WorkspaceID = workspaceID
	snapshot.ForestID = ident.ForestID
	snapshot.DomainSID = ident.DomainSID
	snapshot.DomainDN = ident.DomainDN
	snapshot.InvocationID = ident.InvocationID
	snapshot.ObservedAt = now

	// Per scope: whether every class completed, and the max USN, for the cursor.
	type scopeState struct {
		complete  bool
		maxUSN    int64
		mode      string
		iga       uuid.UUID
		completed map[string][]string // class -> keys, only when that class read finished
	}
	states := map[uuid.UUID]*scopeState{}

	for _, p := range plans {
		st := states[p.scope.ID]
		if st == nil {
			st = &scopeState{complete: true, mode: p.mode, iga: p.iga, completed: map[string][]string{}}
			states[p.scope.ID] = st
		}
		read, err := reader.ReadClass(ctx, p.scope.BaseDN, p.class, p.floor, conn.PageSize)
		cov := directory.ScopeCoverage{BaseDN: p.scope.BaseDN, Class: p.class, ReadMode: p.mode}
		if err != nil {
			st.complete = false
			cov.Reason = "error"
			cov.Complete = false
			coverage = append(coverage, cov)
			continue
		}
		cov.Complete = read.Complete
		cov.Reason = read.Reason
		if !read.Complete {
			st.complete = false
		}
		if read.HighestUSN > st.maxUSN {
			st.maxUSN = read.HighestUSN
		}
		if read.Complete {
			st.completed[p.class] = []string{}
		}
		for _, obj := range read.Objects {
			key, err := igagraph.ADIdentityKey(ident.ForestID, obj.ObjectGUID)
			if err != nil {
				continue
			}
			if err := s.upsertObject(db, workspaceID, integ.ID, p.iga, scan.ID, gen, key, obj, now); err != nil {
				st.complete = false
				cov.Complete = false
				cov.Reason = "error"
				delete(st.completed, p.class)
				continue
			}
			if read.Complete && cov.Complete {
				st.completed[p.class] = append(st.completed[p.class], key)
			}
			cov.Seen++
			snapshot.Objects = append(snapshot.Objects, toSnapshot(obj, key, ident.ForestID))
		}
		coverage = append(coverage, cov)
		_ = s.upsertCoverage(db, workspaceID, integ.ID, p.iga, p.class, cov, now)
	}
	for id, st := range states {
		// Tombstone only classes whose pages all came back, and only on a full
		// read. An incremental cursor cannot see deletions, and a partial page
		// must not be treated as absence.
		if st.mode == "full" {
			for class, keys := range st.completed {
				if err := s.tombstoneAbsent(db, workspaceID, integ.ID, st.iga, class, keys, now); err != nil {
					st.complete = false
				}
			}
		}
		if !st.complete || !conn.ChangeTracking {
			continue
		}
		cur := adldap.Cursor{
			InvocationID: ident.InvocationID,
			HighestUSN:   st.maxUSN,
			Mode:         "usn",
		}
		_ = s.saveCursor(db, workspaceID, id, cur, now)
	}

	status := "succeeded"
	authoritative := true
	for _, c := range coverage {
		if !c.Complete {
			status = "partial"
			authoritative = false
			break
		}
	}
	if len(coverage) == 0 {
		status = "failed"
		authoritative = false
	}
	done := s.now()
	covJSON, _ := json.Marshal(coverage)
	scanStatus := models.ScanSucceeded
	if status == "failed" {
		scanStatus = models.ScanFailed
	}
	counters, _ := json.Marshal(map[string]interface{}{"objects": len(snapshot.Objects), "status": status})
	_ = db.Model(&models.IGAScanRun{}).Where("id = ? AND workspace_id = ?", scan.ID, workspaceID).
		Updates(map[string]interface{}{
			"status": scanStatus, "completed_at": done, "is_authoritative": authoritative && scanStatus == models.ScanSucceeded,
			"counters": counters,
		}).Error
	_ = db.Model(&models.ADInventoryRun{}).Where("id = ? AND workspace_id = ?", runID, workspaceID).
		Updates(map[string]interface{}{
			"status": status, "completed_at": done, "coverage": datatypes.JSON(covJSON),
			"objects_seen": len(snapshot.Objects), "mode": runMode,
		}).Error
	_ = s.saveDirectory(db, workspaceID, row.ID, ident, now)
	return InventoryRunView{
		ID: runID, Status: status, Mode: runMode, ObjectsSeen: len(snapshot.Objects),
		ForestID: ident.ForestID, DomainSID: ident.DomainSID, Coverage: coverage,
		StartedAt: &now, CompletedAt: &done,
	}, nil
}

// GetRun returns one run's status and coverage for this workspace.
func (s *ADInventoryService) GetRun(ctx context.Context, workspaceID, runID uuid.UUID) (InventoryRunView, error) {
	var row models.ADInventoryRun
	err := s.db().WithContext(ctx).Where("id = ? AND workspace_id = ?", runID, workspaceID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return InventoryRunView{}, fmt.Errorf("not found")
	}
	if err != nil {
		return InventoryRunView{}, err
	}
	var cov []directory.ScopeCoverage
	_ = json.Unmarshal(row.Coverage, &cov)
	var inst models.ADDirectoryInstance
	_ = s.db().WithContext(ctx).Where("workspace_id = ? AND sync_config_id = ?", workspaceID, row.SyncConfigID).First(&inst).Error
	return InventoryRunView{
		ID: row.ID, Status: row.Status, Mode: row.Mode, ObjectsSeen: row.ObjectsSeen,
		ForestID: inst.ForestID, DomainSID: inst.DomainSID, Coverage: cov, Error: row.ErrorText,
		StartedAt: row.StartedAt, CompletedAt: row.CompletedAt,
	}, nil
}

// ListObjects returns a page of sanitized objects for the integration bound to
// configID. Payloads are unmarshalled into the allowlisted struct, so a secret
// attribute that somehow landed in JSON is dropped on the way out.
func (s *ADInventoryService) ListObjects(ctx context.Context, workspaceID, configID uuid.UUID, limit, offset int) (ObjectPage, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	db := s.db().WithContext(ctx)
	integ, err := s.findIntegration(db, workspaceID, configID)
	if err != nil {
		return ObjectPage{}, err
	}
	var rows []models.IGASourceObject
	err = db.Where("workspace_id = ? AND integration_id = ? AND lifecycle = ?", workspaceID, integ.ID, models.LifecycleActive).
		Order("recognition_key").Limit(limit + 1).Offset(offset).Find(&rows).Error
	if err != nil {
		return ObjectPage{}, err
	}
	next := false
	if len(rows) > limit {
		next = true
		rows = rows[:limit]
	}
	out := make([]adldap.Object, 0, len(rows))
	for _, row := range rows {
		var obj adldap.Object
		if err := json.Unmarshal(row.NormalizedPayload, &obj); err != nil {
			continue
		}
		obj.Basis = adldap.BasisObserved
		out = append(out, obj)
	}
	page := ObjectPage{Objects: out, Limit: limit, Offset: offset}
	if next {
		n := offset + limit
		page.NextOffset = &n
	}
	return page, nil
}

func (s *ADInventoryService) reader(conn adldap.Conn) (ADReader, error) {
	if s.NewReader != nil {
		return s.NewReader(conn)
	}
	return &adldap.LDAPReader{Conn: conn}, nil
}

func (s *ADInventoryService) loadRow(db *gorm.DB, workspaceID, configID uuid.UUID) (adConnRow, error) {
	var row adConnRow
	err := db.Where("id = ? AND workspace_id = ? AND sync_type = ?", configID, workspaceID, "active_directory").First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return adConnRow{}, fmt.Errorf("sync configuration not found")
	}
	return row, err
}

func (s *ADInventoryService) listScopes(db *gorm.DB, workspaceID, configID uuid.UUID) ([]models.ADInventoryScope, error) {
	var rows []models.ADInventoryScope
	err := db.Where("workspace_id = ? AND sync_config_id = ?", workspaceID, configID).Order("base_dn").Find(&rows).Error
	return rows, err
}

func (s *ADInventoryService) replaceScopes(db *gorm.DB, workspaceID, configID uuid.UUID, scopes []InventoryScope) error {
	keep := map[string]bool{}
	now := s.now()
	for _, sc := range scopes {
		keep[strings.ToLower(sc.BaseDN)] = true
		classes, _ := json.Marshal(sc.ObjectClasses)
		var existing models.ADInventoryScope
		err := db.Where("workspace_id = ? AND sync_config_id = ? AND base_dn = ?", workspaceID, configID, sc.BaseDN).First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			row := models.ADInventoryScope{
				ID: uuid.New(), WorkspaceID: workspaceID, SyncConfigID: configID,
				BaseDN: sc.BaseDN, ObjectClasses: classes, Enabled: sc.Enabled,
				CreatedAt: now, UpdatedAt: now,
			}
			if err := db.Create(&row).Error; err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if err := db.Model(&existing).Updates(map[string]interface{}{
			"object_classes": datatypes.JSON(classes), "enabled": sc.Enabled, "updated_at": now,
		}).Error; err != nil {
			return err
		}
	}
	var existing []models.ADInventoryScope
	if err := db.Where("workspace_id = ? AND sync_config_id = ?", workspaceID, configID).Find(&existing).Error; err != nil {
		return err
	}
	for _, row := range existing {
		if !keep[strings.ToLower(row.BaseDN)] {
			if err := db.Where("workspace_id = ? AND id = ?", workspaceID, row.ID).Delete(&models.ADInventoryScope{}).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ADInventoryService) ensureIntegration(db *gorm.DB, workspaceID uuid.UUID, row adConnRow, ident adldap.Identity, actor string) (models.IGAIntegration, error) {
	host, _, err := net.SplitHostPort(row.ADServer)
	if err != nil {
		host = row.ADServer
	}
	host = strings.ToLower(host)
	appID := "ad-sync:" + row.ID.String()
	var integ models.IGAIntegration
	err = db.Where("workspace_id = ? AND provider = ? AND app_registration_id = ?", workspaceID, "ad", appID).First(&integ).Error
	now := s.now()
	install := ident.ForestID
	caps, _ := json.Marshal(map[string]interface{}{"change_tracking": row.ADChangeTracking, "tracking_mode": row.ADTrackingMode})
	requested, _ := json.Marshal(map[string]interface{}{"object_classes": adldap.DefaultClasses()})
	empty := json.RawMessage(`{}`)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		integ = models.IGAIntegration{
			ID: uuid.New(), WorkspaceID: workspaceID, Provider: "ad",
			ProviderHost: host, AppRegistrationID: appID, InstallationID: &install,
			AccountNativeID:   strPtr(ident.DomainSID),
			CapabilityProfile: caps, RequestedPermissions: requested, GrantedPermissions: empty,
			Status: "active", SecretRef: "sync_configurations/" + row.ID.String(),
			VerifiedAt: &now, Version: 1, CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		}
		if err := db.Create(&integ).Error; err != nil {
			return models.IGAIntegration{}, err
		}
		return integ, nil
	}
	if err != nil {
		return models.IGAIntegration{}, err
	}
	if err := db.Model(&integ).Updates(map[string]interface{}{
		"provider_host": host, "installation_id": install, "account_native_id": ident.DomainSID,
		"status": "active", "verified_at": now, "updated_at": now,
		"capability_profile": json.RawMessage(caps),
	}).Error; err != nil {
		return models.IGAIntegration{}, err
	}
	integ.InstallationID = &install
	return integ, nil
}

func (s *ADInventoryService) findIntegration(db *gorm.DB, workspaceID, configID uuid.UUID) (models.IGAIntegration, error) {
	appID := "ad-sync:" + configID.String()
	var integ models.IGAIntegration
	err := db.Where("workspace_id = ? AND provider = ? AND app_registration_id = ?", workspaceID, "ad", appID).First(&integ).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return models.IGAIntegration{}, fmt.Errorf("not found")
	}
	return integ, err
}

func (s *ADInventoryService) ensureIGAScope(db *gorm.DB, workspaceID, integrationID uuid.UUID, sc models.ADInventoryScope) (uuid.UUID, error) {
	var existing models.IGAIntegrationScope
	err := db.Where("workspace_id = ? AND integration_id = ? AND native_scope_kind = ? AND native_scope_id = ?",
		workspaceID, integrationID, "ad_base_dn", sc.BaseDN).First(&existing).Error
	now := s.now()
	if errors.Is(err, gorm.ErrRecordNotFound) {
		existing = models.IGAIntegrationScope{
			ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: integrationID,
			NativeScopeKind: "ad_base_dn", NativeScopeID: sc.BaseDN, SelectionState: "selected",
			Filters: json.RawMessage(`{}`), EffectivePermissions: json.RawMessage(`{}`),
			CreatedAt: now, UpdatedAt: now,
		}
		if err := db.Create(&existing).Error; err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	}
	_ = db.Model(&models.ADInventoryScope{}).Where("id = ? AND workspace_id = ?", sc.ID, workspaceID).
		Update("integration_scope_id", existing.ID).Error
	return existing.ID, nil
}

func (s *ADInventoryService) loadCursor(db *gorm.DB, workspaceID, scopeID uuid.UUID) (adldap.Cursor, error) {
	var row models.ADInventoryCursor
	err := db.Where("workspace_id = ? AND scope_id = ?", workspaceID, scopeID).First(&row).Error
	if err != nil {
		return adldap.Cursor{}, err
	}
	return adldap.Cursor{
		InvocationID: row.InvocationID, HighestUSN: row.HighestUSN,
		Mode: row.TrackingMode,
	}, nil
}

func (s *ADInventoryService) saveCursor(db *gorm.DB, workspaceID, scopeID uuid.UUID, cur adldap.Cursor, now time.Time) error {
	var existing models.ADInventoryCursor
	err := db.Where("workspace_id = ? AND scope_id = ?", workspaceID, scopeID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return db.Create(&models.ADInventoryCursor{
			WorkspaceID: workspaceID, ScopeID: scopeID, InvocationID: cur.InvocationID,
			HighestUSN: cur.HighestUSN, TrackingMode: cur.Mode,
			UpdatedAt: now,
		}).Error
	}
	if err != nil {
		return err
	}
	return db.Model(&existing).Updates(map[string]interface{}{
		"invocation_id": cur.InvocationID, "highest_usn": cur.HighestUSN,
		"tracking_mode": cur.Mode, "updated_at": now,
	}).Error
}

func (s *ADInventoryService) nextGeneration(db *gorm.DB, workspaceID, integrationID uuid.UUID) (int64, error) {
	var maxGen *int64
	err := db.Model(&models.IGAScanRun{}).
		Where("workspace_id = ? AND integration_id = ?", workspaceID, integrationID).
		Select("MAX(generation)").Scan(&maxGen).Error
	if err != nil {
		return 0, err
	}
	if maxGen == nil {
		return 1, nil
	}
	return *maxGen + 1, nil
}

func (s *ADInventoryService) upsertObject(db *gorm.DB, workspaceID, integrationID, scopeID, scanID uuid.UUID, gen int64, key string, obj adldap.Object, now time.Time) error {
	payload, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	if leaked(payload) {
		return fmt.Errorf("refusing to store a secret attribute")
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	locator, _ := json.Marshal(map[string]string{
		"distinguished_name": obj.DistinguishedName,
		"sam_account_name":   obj.SAMAccountName,
		"object_sid":         obj.ObjectSID,
	})
	var existing models.IGASourceObject
	err = db.Where("workspace_id = ? AND integration_id = ? AND object_type = ? AND recognition_key = ?",
		workspaceID, integrationID, obj.LDAPClass, key).First(&existing).Error
	genCopy := gen
	if errors.Is(err, gorm.ErrRecordNotFound) {
		existing = models.IGASourceObject{
			ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: integrationID,
			IntegrationScopeID: &scopeID, ObjectType: obj.LDAPClass, RecognitionKey: key,
			NativeID: obj.ObjectGUID, Locator: locator, NormalizedPayload: payload,
			RawHash: hash, SourceSubjectKey: obj.AccountKind, ScanGeneration: &genCopy,
			Lifecycle: models.LifecycleActive, FirstSeenAt: now, LastSeenAt: now,
		}
		if err := db.Create(&existing).Error; err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if err := db.Model(&existing).Updates(map[string]interface{}{
			"integration_scope_id": scopeID, "locator": locator, "normalized_payload": payload,
			"raw_hash": hash, "native_id": obj.ObjectGUID, "scan_generation": gen,
			"last_seen_at": now, "lifecycle": models.LifecycleActive, "tombstoned_at": gorm.Expr("NULL"),
		}).Error; err != nil {
			return err
		}
	}
	dedupe := fmt.Sprintf("%s|%s|%d|%s", obj.LDAPClass, key, gen, hash)
	var obs models.IGAObservation
	err = db.Where("workspace_id = ? AND dedupe_key = ?", workspaceID, dedupe).First(&obs).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return db.Create(&models.IGAObservation{
		ID: uuid.New(), WorkspaceID: workspaceID, SourceObjectID: existing.ID,
		ScanRunID: &scanID, Mode: models.EvidenceObserved, FactPayload: payload,
		EvidenceRef: "ad:" + obj.ObjectGUID, ObservedAt: now, IngestedAt: now,
		NormalizerVersion: adNormalizerVersion, RuleID: "ad.directory.read", RuleVersion: "1",
		DedupeKey: dedupe,
	}).Error
}

func (s *ADInventoryService) upsertCoverage(db *gorm.DB, workspaceID, integrationID, scopeID uuid.UUID, class string, cov directory.ScopeCoverage, now time.Time) error {
	state := models.CoveragePartial
	if cov.Complete {
		state = models.CoverageComplete
	}
	var existing models.IGACoverageState
	err := db.Where("workspace_id = ? AND integration_id = ? AND integration_scope_id = ? AND object_class = ?",
		workspaceID, integrationID, scopeID, class).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		row := models.IGACoverageState{
			ID: uuid.New(), WorkspaceID: workspaceID, IntegrationID: integrationID,
			IntegrationScopeID: scopeID, ObjectClass: class, State: state, ReasonCode: cov.Reason,
			LastAttemptAt: &now, InspectedCount: int64(cov.Seen), UpdatedAt: now,
		}
		if cov.Complete {
			row.LastSuccessAt = &now
		}
		return db.Create(&row).Error
	}
	if err != nil {
		return err
	}
	updates := map[string]interface{}{
		"state": state, "reason_code": cov.Reason, "last_attempt_at": now,
		"inspected_count": cov.Seen, "updated_at": now,
	}
	if cov.Complete {
		updates["last_success_at"] = now
	}
	return db.Model(&existing).Updates(updates).Error
}

func (s *ADInventoryService) tombstoneAbsent(db *gorm.DB, workspaceID, integrationID, scopeID uuid.UUID, class string, seen []string, now time.Time) error {
	q := db.Model(&models.IGASourceObject{}).
		Where("workspace_id = ? AND integration_id = ? AND integration_scope_id = ? AND object_type = ? AND lifecycle = ?",
			workspaceID, integrationID, scopeID, class, models.LifecycleActive)
	if len(seen) > 0 {
		q = q.Where("recognition_key NOT IN ?", seen)
	}
	return q.Updates(map[string]interface{}{
		"lifecycle": models.LifecycleTombstoned, "tombstoned_at": now,
	}).Error
}

func (s *ADInventoryService) saveDirectory(db *gorm.DB, workspaceID, configID uuid.UUID, ident adldap.Identity, now time.Time) error {
	var existing models.ADDirectoryInstance
	err := db.Where("workspace_id = ? AND sync_config_id = ?", workspaceID, configID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return db.Create(&models.ADDirectoryInstance{
			ID: uuid.New(), WorkspaceID: workspaceID, SyncConfigID: configID,
			ForestID: ident.ForestID, DomainSID: ident.DomainSID, DomainDN: ident.DomainDN,
			DNSHostName: ident.DNSHostName, InvocationID: ident.InvocationID, UpdatedAt: now,
		}).Error
	}
	if err != nil {
		return err
	}
	return db.Model(&existing).Updates(map[string]interface{}{
		"forest_id": ident.ForestID, "domain_sid": ident.DomainSID, "domain_dn": ident.DomainDN,
		"dns_host_name": ident.DNSHostName, "invocation_id": ident.InvocationID, "updated_at": now,
	}).Error
}

func leaked(payload []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return true
	}
	for k := range raw {
		if adldap.Denied(k) {
			return true
		}
	}
	return false
}

func toSnapshot(obj adldap.Object, key, forest string) directory.ADObject {
	return directory.ADObject{
		AccountKind: obj.AccountKind, LDAPClass: obj.LDAPClass, SourceKey: key, ForestID: forest,
		ObjectGUID: obj.ObjectGUID, ObjectSID: obj.ObjectSID, DistinguishedName: obj.DistinguishedName,
		SAMAccountName: obj.SAMAccountName, UserPrincipalName: obj.UserPrincipalName,
		DisplayName: obj.DisplayName, MemberOf: obj.MemberOf, Member: obj.Member,
		ServicePrincipalName: obj.ServicePrincipalName, Disabled: obj.AccountFlags.AccountDisabled,
		Basis: directory.BasisObserved,
	}
}

func rowToConn(row adConnRow, password string, production bool) adldap.Conn {
	mode := row.ADTrackingMode
	if mode == "" {
		mode = "usn"
	}
	return adldap.Conn{
		Server: row.ADServer, Username: row.ADUsername, Password: password,
		UseSSL: row.ADUseSSL, StartTLS: row.ADStartTLS, SkipVerify: row.ADSkipVerify,
		CABundle: row.ADCABundle, PageSize: clampADPage(row.ADPageSize), Production: production,
		ChangeTracking: row.ADChangeTracking, TrackingMode: mode,
	}
}

func enabledScopes(in []models.ADInventoryScope) []models.ADInventoryScope {
	var out []models.ADInventoryScope
	for _, s := range in {
		if s.Enabled {
			out = append(out, s)
		}
	}
	return out
}

func decodeClasses(raw []byte) []string {
	var classes []string
	if err := json.Unmarshal(raw, &classes); err != nil || len(classes) == 0 {
		return adldap.DefaultClasses()
	}
	out := make([]string, 0, len(classes))
	for _, c := range classes {
		if _, err := adldap.ClassFilter(c, 0); err == nil {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return adldap.DefaultClasses()
	}
	return out
}

func normalizeScopes(in []InventoryScope) ([]InventoryScope, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("at least one base DN scope is required")
	}
	seen := map[string]bool{}
	out := make([]InventoryScope, 0, len(in))
	for _, sc := range in {
		dn := strings.TrimSpace(sc.BaseDN)
		if dn == "" || strings.ContainsAny(dn, "\x00\n\r") {
			return nil, fmt.Errorf("invalid base DN")
		}
		if seen[strings.ToLower(dn)] {
			continue
		}
		seen[strings.ToLower(dn)] = true
		classes := sc.ObjectClasses
		if len(classes) == 0 {
			classes = adldap.DefaultClasses()
		}
		for _, c := range classes {
			if _, err := adldap.ClassFilter(c, 0); err != nil {
				return nil, err
			}
		}
		// Posted scopes are enabled. Removing a base DN from the list is how an
		// administrator withdraws approval; a zero bool would otherwise disable
		// every scope whose client omitted the field.
		out = append(out, InventoryScope{BaseDN: dn, ObjectClasses: classes, Enabled: true})
	}
	return out, nil
}

func clampADPage(n int) int {
	if n <= 0 {
		return 500
	}
	if n > 1000 {
		return 1000
	}
	return n
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
