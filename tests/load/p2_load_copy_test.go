package load

// Bulk loading for the T6.10 fixture: every generated row goes into
// PostgreSQL through COPY (lib/pq's CopyIn), one table at a time, in foreign
// key order, inside ONE transaction per workspace -- so a fixture is either
// all there or not there at all, and no constraint is deferred or disabled.
//
// Projection throughput is not a §5.6 target, so the fixture is written
// directly (as the scanner and projector would have left the tables), never
// by running a projection per row.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// loadTable is one table's generated rows, in the column order of cols.
type loadTable struct {
	name string
	cols []string
	rows [][]any
}

// loadTables is the fixture's tables in INSERT order: every table after the
// ones its foreign keys reference. iga_lifecycle_event's publication key is
// deferrable, the rest are immediate, so the order is load-bearing.
var loadTableOrder = []struct {
	name string
	cols string
}{
	{"workspaces", "id,name,slug,owner_user_id,workspace_type,workspace_domain,email,status,created_at,updated_at"},
	{"users", "id,workspace_id,email,name,created_at,updated_at"},
	{"cloud_connector", "id,workspace_id,provider,scope_kind,scope_id,auth_ref,status,scan_generation,coverage,attrs,verified_at,created_by,created_at,updated_at"},
	{"iga_estate_scopes", "id,workspace_id,scope_kind,display_name,stage,source_key,created_at,updated_at"},
	{"cloud_scan_run", "id,workspace_id,connector_id,generation,status,trigger,lease_owner,lease_version,attempts,requested_at,started_at,published_at,updated_at,coverage"},
	{"iga_publication", "workspace_id,rev,published_at,scan_run_id,manifest"},
	{"cloud_identity", "id,workspace_id,connector_id,kind,native_id,name,created_at,enabled,attrs,last_seen_generation,first_seen_at,last_seen_at,row_updated_at,trust_document,trust_document_hash,trust_parse_error"},
	{"cloud_workload", "id,workspace_id,connector_id,identity_id,runtime_kind,native_id,name,region,attrs,last_seen_generation,first_seen_at,last_seen_at,row_updated_at"},
	{"cloud_policy", "id,workspace_id,connector_id,policy_kind,native_id,holder_identity_id,name,policy_id,aws_managed,version_id,document,document_hash,document_error,last_seen_generation,first_seen_at,last_seen_at"},
	{"cloud_observation", "id,workspace_id,connector_id,scan_run_id,generation,identity_id,workload_id,policy_id,source_api,surface,surface_state,observed_at,ingested_at,sanitized_facts,content_hash,subject_native_id,last_confirmed_run_id,last_confirmed_at,confirmation_count"},
	{"iga_identity_accounts", "id,workspace_id,estate_scope_id,display_name,account_kind,identity_backing,lifecycle,rollup_state,provider,source_key,continuity,immutable_key,first_seen_at,last_seen_at,retired_reason,provider_attrs,created_at,updated_at"},
	{"iga_workload", "id,workspace_id,estate_scope_id,provider,runtime_kind,display_name,region,stage,lifecycle,retired_reason,source_key,continuity,immutable_key,provider_attrs,first_seen_at,last_seen_at,execution_role_state,execution_role_arn,classification,classification_version,created_at,updated_at"},
	{"iga_policy", "id,workspace_id,provider,policy_kind,display_name,native_ref,source_key,continuity,immutable_key,version_id,document_hash,lifecycle,retired_reason,first_seen_at,last_seen_at"},
	{"iga_entitlements", "id,workspace_id,native_grant_kind,native_rights,normalized_rights,lifecycle,provider,source_key,continuity,immutable_key,first_seen_at,last_seen_at,retired_reason,policy_id,statement_key,sid,statement_index,effect,content_hash,negated,conditional,created_at,updated_at"},
	{"iga_statement_revision", "id,workspace_id,entitlement_id,content_hash,statement,policy_version_id,valid_from,valid_to,first_seen_run_id"},
	{"iga_resources", "id,workspace_id,estate_scope_id,resource_kind,display_name,stage,lifecycle,provider,source_key,continuity,immutable_key,first_seen_at,last_seen_at,retired_reason,provider_attrs,created_at,updated_at"},
	{"iga_entitlement_target", "id,workspace_id,entitlement_id,resource_id,target_mode,ordinal"},
	{"iga_policy_assignment", "id,workspace_id,policy_id,holder_identity_account_id,assignment_kind,basis,state,valid_from,valid_to,last_confirmed_at,last_confirmed_by,ended_reason,source_key,partition_key,connector_id"},
	{"iga_access_edges", "id,workspace_id,subject_kind,subject_id,entitlement_id,direction,path_kind,calculation_state,effective_conclusion,subject_identity_account_id,provider,basis,state,valid_from,valid_to,last_confirmed_at,last_confirmed_by,ended_reason,source_key,partition_key,connector_id,assignment_id,created_at,updated_at"},
	{"iga_external_principal", "id,workspace_id,issuer,subject_claim,mechanism,source_key,first_seen_at,last_seen_at"},
	{"iga_relationship", "id,workspace_id,relationship_type,source_identity_account_id,source_workload_id,source_external_principal_id,target_identity_account_id,basis,state,valid_from,valid_to,last_confirmed_at,last_confirmed_by,ended_reason,source_key,partition_key,connector_id,statement_key,conditions,mechanism,created_at,updated_at"},
	{"iga_object_support", "id,workspace_id,identity_account_id,workload_id,resource_id,entitlement_id,policy_id,connector_id,partition_key,state,first_seen_at,last_confirmed_run_id,last_confirmed_at,ended_reason"},
	{"iga_access_edge_evidence", "id,workspace_id,access_edge_id,observation_id,relation,created_at"},
	{"iga_assignment_evidence", "id,workspace_id,assignment_id,observation_id,relation,created_at"},
	{"iga_relationship_evidence", "id,workspace_id,relationship_id,observation_id,relation,created_at"},
	{"iga_lifecycle_event", "id,workspace_id,rev,scan_run_id,occurred_at,event,reason,identity_account_id,workload_id,resource_id,entitlement_id,policy_id"},
	{"iga_projection_state", "id,workspace_id,estate_scope_id,connector_id,object_class,relationship_type,partition_key,last_run_id,last_generation,coverage_state,reconciled,updated_at"},
	{"iga_workload_classification", "id,workspace_id,workload_id,operation_id,decision,previous,purpose,reason,decided_by_user_id,against_version,request_hash,result_version,undoes_decision_id,decided_at"},
	{"iga_classification_clock", "workspace_id,seq"},
	{"iga_credentials", "id,workspace_id,identity_account_id,credential_type,issuer,key_identifier,lifecycle,provider,source_key,continuity,rotation_posture,first_seen_at,last_seen_at,last_used_at,created_at,updated_at"},
}

// loadRows collects the generated rows of every fixture table.
type loadRows struct {
	byName map[string]*loadTable
}

func newLoadRows() *loadRows {
	r := &loadRows{byName: map[string]*loadTable{}}
	for _, t := range loadTableOrder {
		r.byName[t.name] = &loadTable{name: t.name, cols: strings.Split(t.cols, ",")}
	}
	return r
}

// add appends one row; the value count must match the table's columns, which
// is checked here so a generator mistake fails at the call, not deep in COPY.
func (r *loadRows) add(table string, vals ...any) {
	t, ok := r.byName[table]
	if !ok {
		panic("load: no fixture table " + table)
	}
	if len(vals) != len(t.cols) {
		panic(fmt.Sprintf("load: %s takes %d values, got %d", table, len(t.cols), len(vals)))
	}
	for i, v := range vals {
		vals[i] = loadCopyValue(v)
	}
	t.rows = append(t.rows, vals)
}

// count is how many rows a table holds so far.
func (r *loadRows) count(table string) int { return len(r.byName[table].rows) }

// loadCopyValue converts a Go value into what lib/pq's COPY text encoding
// takes. JSON documents go as text (a []byte would be sent as bytea and
// rejected by jsonb); uuids as their string; nil pointers as NULL.
func loadCopyValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case uuid.UUID:
		return x.String()
	case *uuid.UUID:
		if x == nil {
			return nil
		}
		return x.String()
	case *time.Time:
		if x == nil {
			return nil
		}
		return *x
	case json.RawMessage:
		if x == nil {
			return nil
		}
		return string(x)
	case loadJSON:
		return string(x)
	case *string:
		if x == nil {
			return nil
		}
		return *x
	case *int:
		if x == nil {
			return nil
		}
		return int64(*x)
	case int:
		return int64(x)
	}
	return v
}

// loadJSON is a JSON document destined for a json/jsonb column.
type loadJSON string

// loadMarshal renders v as a loadJSON, panicking on a generator bug.
func loadMarshal(v any) loadJSON {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("load: marshal %T: %v", v, err))
	}
	return loadJSON(b)
}

// write COPYs every table in order inside one transaction.
func (r *loadRows) write(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	for _, spec := range loadTableOrder {
		t := r.byName[spec.name]
		if len(t.rows) == 0 {
			continue
		}
		stmt, err := tx.Prepare(pq.CopyIn(t.name, t.cols...))
		if err != nil {
			return fmt.Errorf("copy %s: %w", t.name, err)
		}
		for _, row := range t.rows {
			if _, err := stmt.Exec(row...); err != nil {
				_ = stmt.Close()
				return fmt.Errorf("copy %s row: %w", t.name, err)
			}
		}
		if _, err := stmt.Exec(); err != nil {
			_ = stmt.Close()
			return fmt.Errorf("copy %s flush: %w", t.name, err)
		}
		if err := stmt.Close(); err != nil {
			return fmt.Errorf("copy %s close: %w", t.name, err)
		}
	}
	return tx.Commit()
}

// loadWipe removes every workspace a previous fixture build left, table by
// table in reverse dependency order. Several foreign keys are RESTRICT
// (iga_publication, the observation junctions, run references), so deleting
// the workspace row alone would fail part-way.
func loadWipe(db *sql.DB, namePrefix string) error {
	var ids []string
	rows, err := db.Query(`SELECT id::text FROM workspaces WHERE name LIKE $1`, namePrefix+"%")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) == 0 {
		return nil
	}
	arr := pq.Array(ids)
	for i := len(loadTableOrder) - 1; i >= 0; i-- {
		name := loadTableOrder[i].name
		col := "workspace_id"
		if name == "workspaces" {
			col = "id"
		}
		if _, err := db.Exec(`DELETE FROM `+name+` WHERE `+col+`::text = ANY($1)`, arr); err != nil {
			return fmt.Errorf("wipe %s: %w", name, err)
		}
	}
	return nil
}
