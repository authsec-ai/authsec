package services

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/auditchain"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
)

// The audit_events hash chain (migration 167): anchors, the retention purge
// that keeps chains verifiable, and verification.
//
// Why gaps and not only anchors: retention differs per record class and
// legal holds keep rows inside purged windows, so a purge removes runs of
// links from the MIDDLE of a chain, not just its oldest prefix. Each run is
// recorded (audit_chain_gap: the hash before it and the hash of its last
// link) so the walk crosses it and the surviving rows still link up; a link
// missing without a gap row is reported (missing_rows). The chain head is
// anchored before every purge, and the newest link of a chain is never
// purged (the trigger reads the head from it).

const (
	auditPurgeBatch     = 5000
	auditVerifyMaxRows  = 200000
	auditRetentionFlag  = `SET LOCAL authsec.audit_retention = 'on'`
	auditAnchorDaily    = "daily"
	auditAnchorPurge    = "purge"
	auditVerifyMaxRange = (MaxAuditRetentionDays + 1) * 24 * time.Hour
)

type auditHead struct {
	Seq  int64
	Hash string
}

func chainHead(tx *gorm.DB, chain string) (*auditHead, error) {
	var rows []auditHead
	if err := tx.Raw(`SELECT seq, hash FROM audit_events WHERE workspace_id = ? AND seq IS NOT NULL ORDER BY seq DESC LIMIT 1`, chain).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// anchorChain records the chain's head; it returns the head and whether a new
// anchor row was written (an unchanged head is anchored once).
func anchorChain(tx *gorm.DB, ws *uuid.UUID, chain, reason string, now time.Time) (*auditHead, bool, error) {
	head, err := chainHead(tx, chain)
	if err != nil || head == nil {
		return head, false, err
	}
	res := tx.Exec(`INSERT INTO audit_chain_anchor (workspace_id, chain, day, last_seq, head_hash, reason)
	                VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (chain, last_seq) DO NOTHING`,
		ws, chain, now.UTC().Format("2006-01-02"), head.Seq, head.Hash, reason)
	return head, res.RowsAffected > 0, res.Error
}

// AnchorWorkspace anchors the workspace's chain (the daily job).
func (s *AuditGovService) AnchorWorkspace(ctx context.Context, ws uuid.UUID) error {
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		head, added, err := anchorChain(tx, &ws, ws.String(), auditAnchorDaily, s.now())
		if err != nil || !added {
			return err
		}
		return appendGovEvent(tx, ws, GovEventAuditAnchored, models.GovActorSystem, "", govEventRefs{},
			map[string]any{"last_seq": head.Seq, "head_hash": head.Hash})
	})
}

// AuditAnchor is a recorded chain head.
type AuditAnchor struct {
	Day       string    `json:"day"`
	LastSeq   int64     `json:"last_seq"`
	HeadHash  string    `json:"head_hash"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// Anchors lists the workspace's newest anchors.
func (s *AuditGovService) Anchors(ctx context.Context, ws uuid.UUID, limit int) ([]AuditAnchor, error) {
	if limit <= 0 || limit > 400 {
		limit = 100
	}
	var out []AuditAnchor
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT to_char(day, 'YYYY-MM-DD') AS day, last_seq, head_hash, reason, created_at
		               FROM audit_chain_anchor WHERE workspace_id = ? ORDER BY last_seq DESC LIMIT ?`, ws, limit).Scan(&out).Error
	})
	return out, err
}

/* ---------------------------------- purge ---------------------------------- */

// AuditPurgeResult counts one purge of one chain.
type AuditPurgeResult struct {
	Deleted int64 `json:"deleted"`
	Gaps    int   `json:"gaps"`
}

type auditHold struct {
	FromTS, ToTS time.Time
}

type purgedLink struct {
	Seq      *int64
	PrevHash *string
	Hash     *string
}

// purgeChain deletes the chain's expired rows in batches inside tx (which
// carries the retention flag), never the head link nor a row under a live
// hold, and records each run of removed links as a gap.
func purgeChain(tx *gorm.DB, ws *uuid.UUID, chain string, days map[string]int, holds []auditHold, now time.Time) (AuditPurgeResult, error) {
	var out AuditPurgeResult
	if err := tx.Exec(auditRetentionFlag).Error; err != nil {
		return out, err
	}
	head, _, err := anchorChain(tx, ws, chain, auditAnchorPurge, now)
	if err != nil {
		return out, err
	}
	headSeq := int64(1) << 62
	if head != nil {
		headSeq = head.Seq
	}
	run := uuid.New()
	// Holds are applied in SQL from the list read in this transaction.
	holdSQL := ""
	var holdArgs []any
	for _, h := range holds {
		holdSQL += ` AND NOT (COALESCE(e."timestamp", e.created_at) >= ? AND COALESCE(e."timestamp", e.created_at) < ?)`
		holdArgs = append(holdArgs, h.FromTS, h.ToTS)
	}
	classes := append([]string{}, monitoring.AuditRecordClasses...)
	sort.Strings(classes)
	for {
		var batch []purgedLink
		more := false
		for _, class := range classes {
			cutoff := now.UTC().AddDate(0, 0, -days[class])
			args := []any{chain, class, cutoff, headSeq}
			args = append(args, holdArgs...)
			args = append(args, auditPurgeBatch)
			var got []purgedLink
			if err := tx.Raw(`DELETE FROM audit_events WHERE id IN (
			        SELECT e.id FROM audit_events e
			         WHERE e.workspace_id = ? AND COALESCE(e.record_class, 'default') = ?
			           AND COALESCE(e."timestamp", e.created_at) < ?
			           AND (e.seq IS NULL OR e.seq < ?)`+holdSQL+`
			         ORDER BY e.seq NULLS FIRST, e.id LIMIT ?)
			      RETURNING seq, prev_hash, hash`, args...).Scan(&got).Error; err != nil {
				return out, err
			}
			if len(got) == auditPurgeBatch {
				more = true
			}
			batch = append(batch, got...)
		}
		out.Deleted += int64(len(batch))
		n, err := recordGaps(tx, ws, chain, batch, run)
		if err != nil {
			return out, err
		}
		out.Gaps += n
		if !more {
			return out, nil
		}
	}
}

// recordGaps inserts one gap per run of consecutive seqs in links.
func recordGaps(tx *gorm.DB, ws *uuid.UUID, chain string, links []purgedLink, run uuid.UUID) (int, error) {
	var chained []purgedLink
	for _, l := range links {
		if l.Seq != nil && l.PrevHash != nil && l.Hash != nil {
			chained = append(chained, l)
		}
	}
	sort.Slice(chained, func(i, j int) bool { return *chained[i].Seq < *chained[j].Seq })
	n := 0
	for i := 0; i < len(chained); {
		j := i
		for j+1 < len(chained) && *chained[j+1].Seq == *chained[j].Seq+1 {
			j++
		}
		if err := tx.Exec(`INSERT INTO audit_chain_gap (workspace_id, chain, from_seq, to_seq, prev_hash, last_hash, purge_run)
		                   VALUES (?, ?, ?, ?, ?, ?, ?)`,
			ws, chain, *chained[i].Seq, *chained[j].Seq, *chained[i].PrevHash, *chained[j].Hash, run).Error; err != nil {
			return n, err
		}
		n++
		i = j + 1
	}
	return n, nil
}

func liveHolds(tx *gorm.DB, ws uuid.UUID) ([]auditHold, error) {
	var holds []auditHold
	err := tx.Raw(`SELECT from_ts, to_ts FROM audit_legal_hold WHERE workspace_id = ? AND released_at IS NULL ORDER BY from_ts`, ws).
		Scan(&holds).Error
	return holds, err
}

// PurgeWorkspace applies the workspace's retention to its audit events: per
// record class, sparing live legal holds and the chain head, anchoring
// first and recording the gaps; the purge itself is audited in the chain.
func (s *AuditGovService) PurgeWorkspace(ctx context.Context, ws uuid.UUID) (AuditPurgeResult, error) {
	var out AuditPurgeResult
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		days, _, err := readAuditRetention(tx, ws)
		if err != nil {
			return err
		}
		holds, err := liveHolds(tx, ws)
		if err != nil {
			return err
		}
		if out, err = purgeChain(tx, &ws, ws.String(), days, holds, s.now()); err != nil {
			return err
		}
		if out.Deleted == 0 {
			return nil
		}
		if err := writeAudit(tx, ws, AuditActor{}, "audit.retention_purged", "audit_events", "", 200, nil,
			map[string]any{"deleted": out.Deleted, "gaps": out.Gaps, "retention_days": days, "legal_holds": len(holds)}); err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventAuditRetentionPurged, models.GovActorSystem, "", govEventRefs{},
			map[string]any{"deleted": out.Deleted, "gaps": out.Gaps})
	})
	return out, err
}

// purgePlatformChain applies the built-in retention to a chain that belongs
// to no live workspace (pre-auth events, or a deleted workspace's).
func (s *AuditGovService) purgePlatformChain(ctx context.Context, chain string) (AuditPurgeResult, error) {
	var out AuditPurgeResult
	// TENANT-EXEMPT: the platform chain (events with no live workspace) has no tenant; it is purged with the built-in retention.
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		out, err = purgeChain(tx, nil, chain, DefaultAuditRetentionDays, nil, s.now())
		return err
	})
	return out, err
}

// auditChains lists every chain key in audit_events, split into live
// workspaces and the rest (platform).
func (s *AuditGovService) auditChains(ctx context.Context) (wss []uuid.UUID, platform []string, err error) {
	var keys []string
	// TENANT-EXEMPT: the retention and anchor jobs run across workspaces; this lists chain keys only, each chain is then handled in its own workspace transaction.
	if err = s.db.WithContext(ctx).Raw(`SELECT DISTINCT COALESCE(workspace_id, '') FROM audit_events`).Scan(&keys).Error; err != nil {
		return nil, nil, err
	}
	var live []string
	// TENANT-EXEMPT: workspaces is the tenant registry (no workspace_id column); this checks which chain keys name a live workspace.
	if err = s.db.WithContext(ctx).Raw(`SELECT id::text FROM workspaces`).Scan(&live).Error; err != nil {
		return nil, nil, err
	}
	isLive := map[string]bool{}
	for _, l := range live {
		isLive[l] = true
	}
	sort.Strings(keys)
	for _, k := range keys {
		if id, perr := uuid.Parse(k); perr == nil && isLive[k] && id.String() == k {
			wss = append(wss, id)
		} else {
			platform = append(platform, k)
		}
	}
	return wss, platform, nil
}

// PurgeAll anchors and purges every chain; the first error is returned after
// every chain was tried.
func (s *AuditGovService) PurgeAll(ctx context.Context) error {
	wss, platform, err := s.auditChains(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, ws := range wss {
		if _, err := s.PurgeWorkspace(ctx, ws); err != nil && first == nil {
			first = fmt.Errorf("workspace %s: %w", ws, err)
		}
	}
	for _, chain := range platform {
		if _, err := s.purgePlatformChain(ctx, chain); err != nil && first == nil {
			first = fmt.Errorf("platform chain %q: %w", chain, err)
		}
	}
	return first
}

// AnchorAll anchors every chain (daily).
func (s *AuditGovService) AnchorAll(ctx context.Context) error {
	wss, platform, err := s.auditChains(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, ws := range wss {
		if err := s.AnchorWorkspace(ctx, ws); err != nil && first == nil {
			first = fmt.Errorf("workspace %s: %w", ws, err)
		}
	}
	for _, chain := range platform {
		// TENANT-EXEMPT: the platform chain has no tenant; anchoring it writes a workspace_id NULL row.
		err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			_, _, err := anchorChain(tx, nil, chain, auditAnchorDaily, s.now())
			return err
		})
		if err != nil && first == nil {
			first = fmt.Errorf("platform chain %q: %w", chain, err)
		}
	}
	return first
}

/* ------------------------------- verification ------------------------------ */

// AuditVerifyReport is the outcome of recomputing a window of the chain.
type AuditVerifyReport struct {
	OK             bool               `json:"ok"`
	From           time.Time          `json:"from"`
	To             time.Time          `json:"to"`
	FirstSeq       int64              `json:"first_seq"`
	LastSeq        int64              `json:"last_seq"`
	RowsChecked    int64              `json:"rows_checked"`
	GapsCrossed    int64              `json:"gaps_crossed"`
	AnchorsChecked int                `json:"anchors_checked"`
	UnchainedRows  int64              `json:"unchained_rows"`
	Truncated      bool               `json:"truncated"`
	Breaks         []auditchain.Break `json:"breaks"`
}

type auditVerifyRow struct {
	ID          int64
	WorkspaceID string
	Seq         int64
	PrevHash    string
	Hash        string
	RecordClass *string
	RequestID   *string
	ActorRealm  *string
	UserID      *string
	Action      *string
	Resource    *string
	ResourceID  *string
	Method      *string
	Path        *string
	UserAgent   *string
	ClientIP    *string
	StatusCode  *int64
	Duration    *int64
	OldValues   *string
	NewValues   *string
	Error       *string
	Timestamp   *time.Time
}

// Verify recomputes every link of the workspace's chain whose row falls in
// [from, to] (and the links between them), starting from the surviving link
// before the window or across the gaps that lead to it, and checks the
// anchors inside it. Unchained rows (written before migration 167) are
// counted, not verified.
func (s *AuditGovService) Verify(ctx context.Context, ws uuid.UUID, from, to time.Time) (*AuditVerifyReport, error) {
	if !to.After(from) {
		return nil, GovBadParam("to", "to must be after from.")
	}
	if to.Sub(from) > auditVerifyMaxRange {
		return nil, GovBadParam("from", "The window may span at most the longest retention (7 years).")
	}
	chain := ws.String()
	rep := &AuditVerifyReport{From: from.UTC(), To: to.UTC(), Breaks: []auditchain.Break{}}
	ctx = tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: ws})
	err := tenancy.RLSTransaction(ctx, s.db, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(tx *gorm.DB, _ uuid.UUID) error {
		if err := tx.Raw(`SELECT count(*) FROM audit_events WHERE workspace_id = ? AND seq IS NULL
		                    AND COALESCE("timestamp", created_at) >= ? AND COALESCE("timestamp", created_at) <= ?`, chain, from, to).
			Scan(&rep.UnchainedRows).Error; err != nil {
			return err
		}
		var bounds struct{ Lo, Hi *int64 }
		if err := tx.Raw(`SELECT min(seq) AS lo, max(seq) AS hi FROM audit_events WHERE workspace_id = ? AND seq IS NOT NULL
		                    AND "timestamp" >= ? AND "timestamp" <= ?`, chain, from, to).Scan(&bounds).Error; err != nil {
			return err
		}
		if bounds.Lo == nil {
			return nil
		}
		lo, hi := *bounds.Lo, *bounds.Hi
		// The walk starts after the newest surviving link before lo (or at
		// the chain's start) and crosses recorded gaps up to lo.
		var pred []auditHead
		if err := tx.Raw(`SELECT seq, hash FROM audit_events WHERE workspace_id = ? AND seq IS NOT NULL AND seq < ?
		                  ORDER BY seq DESC LIMIT 1`, chain, lo).Scan(&pred).Error; err != nil {
			return err
		}
		startSeq, startHash := int64(1), auditchain.Genesis
		if len(pred) == 1 {
			startSeq, startHash = pred[0].Seq+1, pred[0].Hash
		}
		var gaps []auditchain.Gap
		if err := tx.Raw(`SELECT from_seq, to_seq, prev_hash, last_hash FROM audit_chain_gap
		                  WHERE workspace_id = ? AND chain = ? AND to_seq >= ? AND from_seq <= ?`, ws, chain, startSeq, hi).
			Scan(&gaps).Error; err != nil {
			return err
		}
		v := auditchain.NewVerifier(gaps)
		v.Start(startSeq, startHash, true)
		rows, err := tx.Raw(`SELECT id, workspace_id, seq, prev_hash, hash, record_class, request_id, actor_realm, user_id, action,
		                            resource, resource_id, method, path, user_agent, client_ip, status_code, duration,
		                            old_values::text AS old_values, new_values::text AS new_values, error, "timestamp"
		                       FROM audit_events WHERE workspace_id = ? AND seq BETWEEN ? AND ? ORDER BY seq LIMIT ?`,
			chain, lo, hi, auditVerifyMaxRows+1).Rows()
		if err != nil {
			return err
		}
		defer rows.Close()
		last := lo
		for rows.Next() {
			var r auditVerifyRow
			if err := tx.ScanRows(rows, &r); err != nil {
				return err
			}
			if v.Rows >= auditVerifyMaxRows {
				rep.Truncated = true
				break
			}
			v.Next(auditchain.Row(r))
			last = r.Seq
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if !rep.Truncated {
			last = hi
		}
		var anchors []auditchain.Anchor
		if err := tx.Raw(`SELECT last_seq, head_hash, to_char(day, 'YYYY-MM-DD') AS day FROM audit_chain_anchor
		                  WHERE workspace_id = ? AND chain = ? AND last_seq BETWEEN ? AND ?`, ws, chain, startSeq, last).
			Scan(&anchors).Error; err != nil {
			return err
		}
		rep.AnchorsChecked = v.Finish(last, anchors)
		rep.FirstSeq, rep.LastSeq, rep.RowsChecked, rep.GapsCrossed = v.FirstSeq, v.LastSeq, v.Rows, v.GapsCrossed
		rep.Breaks = append(rep.Breaks, v.Breaks...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	rep.OK = len(rep.Breaks) == 0
	return rep, nil
}
