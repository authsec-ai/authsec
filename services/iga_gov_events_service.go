package services

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// The events API (SPEC-iga-phase3-policy.md §7.8, §9.6, E-10; T3.20):
// iga_gov_event, the append-only audit behind Logs, read with filters and
// exported. Payloads are redacted (RedactGovEventPayload) on the way out.
//
//	GET /events?kind&category&object_kind&object_id&actor&actor_kind&from&to&cursor&limit
//	    newest first, cursor-paged (limit <= 200)
//	GET /events/export?<same filter>&format=csv|json
//	    oldest first (the chain in order), streamed, every matching event
//
// DECISIONS (T3.20):
//   - format=json is NDJSON (one event per line, application/x-ndjson):
//     streamable and loadable line by line; "ndjson" is accepted as an
//     alias. CSV carries the payload as one JSON column.
//   - kind is a comma-separated list (or repeated) of event names; a name
//     ending in ".*" is a prefix ("review.*"). category expands to the
//     vocabulary's names for that Logs category.
//   - object_kind/object_id: policy, version, deployment and finding are
//     iga_gov_event columns; the other kinds are the payload key their
//     writers use (GovEventObjectKinds); workload and identity_account match
//     payload object_kind + object_id (owners.set, owner.review_date_set).
//   - actor is the actor id (a user id, "policy-worker", "evaluator", ...);
//     actor_kind is user | system | slack_user | aws.
//   - from is inclusive, to exclusive (RFC 3339).

// GovEventFilter is the events API's filter.
type GovEventFilter struct {
	Kinds      []string
	Category   string
	ObjectKind string
	ObjectID   *uuid.UUID
	Actor      string
	ActorKind  string
	From, To   *time.Time
}

// GovEventView is one event as the API returns it.
type GovEventView struct {
	ID           int64           `json:"id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	Event        string          `json:"event"`
	Category     string          `json:"category"`
	ActorKind    string          `json:"actor_kind"`
	ActorID      string          `json:"actor_id"`
	PolicyID     *uuid.UUID      `json:"policy_id"`
	VersionID    *uuid.UUID      `json:"version_id"`
	DeploymentID *uuid.UUID      `json:"deployment_id"`
	FindingID    *uuid.UUID      `json:"finding_id"`
	Payload      json.RawMessage `json:"payload"`
}

var reGovEventKind = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*(\.\*)?$`)

// ParseGovEventFilter validates the raw query values.
func ParseGovEventFilter(kinds []string, category, objectKind, objectID, actor, actorKind, from, to string) (GovEventFilter, error) {
	var f GovEventFilter
	for _, k := range kinds {
		for _, p := range strings.Split(k, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !reGovEventKind.MatchString(p) {
				return f, GovBadParam("kind", "kind must be event names (a trailing .* is a prefix).")
			}
			f.Kinds = append(f.Kinds, p)
		}
	}
	sort.Strings(f.Kinds)
	if category != "" {
		found := false
		for _, c := range GovEventCategories() {
			if c.Category == category {
				found = true
			}
		}
		if !found {
			return f, GovBadParam("category", "Unknown event category.")
		}
		f.Category = category
	}
	if objectKind != "" {
		if _, ok := govEventObjectFilters[objectKind]; !ok {
			return f, GovBadParam("object_kind", "object_kind must be one of "+strings.Join(GovEventObjectKinds(), ", ")+".")
		}
		f.ObjectKind = objectKind
	}
	if objectID != "" {
		id, err := uuid.Parse(objectID)
		if err != nil {
			return f, GovBadParam("object_id", "object_id must be a uuid.")
		}
		f.ObjectID = &id
	}
	if (f.ObjectKind == "") != (f.ObjectID == nil) {
		return f, GovBadParam("object_kind", "object_kind and object_id go together.")
	}
	f.Actor = strings.TrimSpace(actor)
	if actorKind != "" {
		switch actorKind {
		case models.GovActorUser, models.GovActorSystem, models.GovActorSlackUser, models.GovActorAWS:
		default:
			return f, GovBadParam("actor_kind", "actor_kind must be user, system, slack_user or aws.")
		}
		f.ActorKind = actorKind
	}
	for _, x := range []struct {
		name string
		raw  string
		dst  **time.Time
	}{{"from", from, &f.From}, {"to", to, &f.To}} {
		if x.raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, x.raw)
		if err != nil {
			return f, GovBadParam(x.name, x.name+" must be an RFC 3339 time.")
		}
		*x.dst = &t
	}
	if f.From != nil && f.To != nil && !f.From.Before(*f.To) {
		return f, GovBadParam("to", "to must be after from.")
	}
	return f, nil
}

// key is the filter's canonical form (cursor binding).
func (f GovEventFilter) key() string {
	parts := []string{"k=" + strings.Join(f.Kinds, ","), "c=" + f.Category, "ok=" + f.ObjectKind, "a=" + f.Actor, "ak=" + f.ActorKind}
	if f.ObjectID != nil {
		parts = append(parts, "oi="+f.ObjectID.String())
	}
	if f.From != nil {
		parts = append(parts, "f="+f.From.UTC().Format(time.RFC3339Nano))
	}
	if f.To != nil {
		parts = append(parts, "t="+f.To.UTC().Format(time.RFC3339Nano))
	}
	return strings.Join(parts, ";")
}

func (f GovEventFilter) apply(q *gorm.DB, ws uuid.UUID) *gorm.DB {
	q = q.Where("workspace_id = ?", ws)
	names := map[string]bool{}
	var prefixes []string
	for _, k := range f.Kinds {
		if strings.HasSuffix(k, ".*") {
			prefixes = append(prefixes, strings.TrimSuffix(k, "*"))
		} else {
			names[k] = true
		}
	}
	if len(f.Kinds) > 0 {
		cond := "false"
		var args []any
		if len(names) > 0 {
			list := make([]string, 0, len(names))
			for n := range names {
				list = append(list, n)
			}
			sort.Strings(list)
			cond += " OR event IN ?"
			args = append(args, list)
		}
		for _, p := range prefixes {
			cond += " OR starts_with(event, ?)"
			args = append(args, p)
		}
		q = q.Where("("+cond+")", args...)
	}
	if f.Category != "" {
		var list []string
		for _, k := range GovEventVocabulary {
			if k.Category == f.Category {
				list = append(list, k.Name)
			}
		}
		if len(list) == 0 {
			q = q.Where("false")
		} else {
			q = q.Where("event IN ?", list)
		}
	}
	if f.ObjectKind != "" && f.ObjectID != nil {
		of := govEventObjectFilters[f.ObjectKind]
		switch {
		case of.column != "":
			q = q.Where(of.column+" = ?", *f.ObjectID)
		case f.ObjectKind == GovObjWorkload || f.ObjectKind == GovObjIdentityAccount:
			q = q.Where("payload->>'object_kind' = ? AND payload->>'object_id' = ?", f.ObjectKind, f.ObjectID.String())
		default:
			q = q.Where("payload->>'"+of.payloadKey+"' = ?", f.ObjectID.String())
		}
	}
	if f.Actor != "" {
		q = q.Where("actor_id = ?", f.Actor)
	}
	if f.ActorKind != "" {
		q = q.Where("actor_kind = ?", f.ActorKind)
	}
	if f.From != nil {
		q = q.Where("occurred_at >= ?", *f.From)
	}
	if f.To != nil {
		q = q.Where("occurred_at < ?", *f.To)
	}
	return q
}

func govEventView(e models.IGAGovEvent) GovEventView {
	return GovEventView{ID: e.ID, OccurredAt: e.OccurredAt, Event: e.Event, Category: GovEventCategory(e.Event),
		ActorKind: e.ActorKind, ActorID: e.ActorID, PolicyID: e.PolicyID, VersionID: e.VersionID,
		DeploymentID: e.DeploymentID, FindingID: e.FindingID, Payload: RedactGovEventPayload(e.Payload)}
}

// GovEventsService serves the events API.
type GovEventsService struct {
	db  *gorm.DB
	key []byte
}

// NewGovEventsService builds the service; key signs cursors.
func NewGovEventsService(db *gorm.DB, cursorKey []byte) *GovEventsService {
	return &GovEventsService{db: db, key: cursorKey}
}

// List is GET /events: newest first.
func (s *GovEventsService) List(ctx context.Context, ws uuid.UUID, f GovEventFilter, cursor string, limit int) ([]GovEventView, *string, error) {
	if limit <= 0 || limit > MaxGovPage {
		limit = MaxGovPage
	}
	rd := NewGovReader(s.db, s.key)
	want := govCursor{Route: "events", WS: ws.String(), Q: f.key()}
	q := f.apply(s.db.WithContext(ctx).Model(&models.IGAGovEvent{}), ws)
	if cursor != "" {
		after, err := rd.open(cursor, want)
		if err != nil {
			return nil, nil, err
		}
		id, err := strconv.ParseInt(after, 10, 64)
		if err != nil {
			return nil, nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid for this list; restart it.", nil)
		}
		q = q.Where("id < ?", id)
	}
	var rows []models.IGAGovEvent
	if err := q.Order("id DESC").Limit(limit + 1).Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		c := rd.sign(govCursor{Route: want.Route, WS: want.WS, Q: want.Q, After: strconv.FormatInt(rows[len(rows)-1].ID, 10)})
		next = &c
	}
	out := make([]GovEventView, 0, len(rows))
	for _, e := range rows {
		out = append(out, govEventView(e))
	}
	return out, next, nil
}

// Export formats.
const (
	GovExportCSV    = "csv"
	GovExportNDJSON = "json"
)

// ParseGovExportFormat accepts csv, json and ndjson.
func ParseGovExportFormat(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "json", "ndjson":
		return GovExportNDJSON, nil
	case "csv":
		return GovExportCSV, nil
	}
	return "", GovBadParam("format", "format must be csv or json.")
}

// GovEventCSVHeader is the export's CSV header.
var GovEventCSVHeader = []string{"id", "occurred_at", "event", "category", "actor_kind", "actor_id",
	"policy_id", "version_id", "deployment_id", "finding_id", "payload"}

const govExportBatch = 500

// Export streams every matching event, oldest first, to w in format;
// flush (optional) runs after each batch. It returns the number written.
func (s *GovEventsService) Export(ctx context.Context, ws uuid.UUID, f GovEventFilter, format string, w io.Writer, flush func()) (int, error) {
	var cw *csv.Writer
	if format == GovExportCSV {
		cw = csv.NewWriter(w)
		if err := cw.Write(GovEventCSVHeader); err != nil {
			return 0, err
		}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	var last int64
	n := 0
	for {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		var rows []models.IGAGovEvent
		q := f.apply(s.db.WithContext(ctx).Model(&models.IGAGovEvent{}), ws).Where("id > ?", last)
		if err := q.Order("id").Limit(govExportBatch).Find(&rows).Error; err != nil {
			return n, err
		}
		for _, e := range rows {
			v := govEventView(e)
			if cw != nil {
				if err := cw.Write([]string{strconv.FormatInt(v.ID, 10), v.OccurredAt.UTC().Format(time.RFC3339Nano), v.Event,
					v.Category, v.ActorKind, v.ActorID, uuidCell(v.PolicyID), uuidCell(v.VersionID), uuidCell(v.DeploymentID),
					uuidCell(v.FindingID), string(v.Payload)}); err != nil {
					return n, err
				}
			} else if err := enc.Encode(v); err != nil {
				return n, err
			}
			n++
			last = e.ID
		}
		if cw != nil {
			cw.Flush()
			if err := cw.Error(); err != nil {
				return n, err
			}
		}
		if flush != nil {
			flush()
		}
		if len(rows) < govExportBatch {
			return n, nil
		}
	}
}

func uuidCell(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// GovExportFilename is the export's attachment name.
func GovExportFilename(format string, now time.Time) string {
	ext := "ndjson"
	if format == GovExportCSV {
		ext = "csv"
	}
	return fmt.Sprintf("authsec-policy-events-%s.%s", now.UTC().Format("20060102T150405Z"), ext)
}
