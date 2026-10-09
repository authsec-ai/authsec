package igagovschema_test

// Every Phase 3 table has a Go model whose columns are EXACTLY the table's
// (no missing column, no column the table does not have) and whose primary
// key is the table's. A model that drifted from its migration fails here, not
// at a runtime INSERT.

import (
	"sort"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm/schema"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

func phase3Models() []any {
	return []any{
		&models.IGAGovOwnerRule{}, &models.IGAGovOwner{},
		&models.IGAGovEvaluation{}, &models.IGAGovActivityEvidence{}, &models.IGAGovFinding{},
		&models.IGAGovFindingResult{}, &models.IGAGovFindingRule{},
		&models.IGAGovPolicy{}, &models.IGAGovPolicyVersion{}, &models.IGAGovDocument{},
		&models.IGAGovControl{}, &models.IGAGovTarget{},
		&models.IGAGovEvidenceBundle{}, &models.IGAGovPlan{}, &models.IGAGovOwnerReview{},
		&models.IGAGovOwnerResponse{}, &models.IGAGovApproval{}, &models.IGAGovRevalidation{},
		&models.IGAGovRollout{}, &models.IGAGovAcceptance{}, &models.IGAGovDeployment{},
		&models.IGAGovAttempt{}, &models.IGAGovVerification{}, &models.IGAGovServiceOutcome{},
		&models.IGAGovServicePosture{}, &models.IGAGovArtifact{}, &models.IGAGovWorkloadMigration{},
		&models.IGAGovHealthReport{}, &models.IGAGovValidation{}, &models.IGAGovValidationItem{},
		&models.IGAGovJob{}, &models.IGAGovEvent{}, &models.IGAGovMetricsHourly{},
		&models.CloudEnforcementBinding{}, &models.IGAGovIaCSource{}, &models.IGAGovIaCChange{},
		&models.WorkspaceSlackIntegration{}, &models.SlackUserLink{}, &models.IGAGovNotification{},
		&models.IGAGovSettings{},
		&models.CloudPolicyDocument{}, &models.CloudResourcePolicyCoverage{}, &models.CloudResourcePolicyObservation{},
		&models.IGAGovEvaluationPruned{}, // 059_tidy_eval_pruned
	}
}

func TestPhase3ModelsMatchTables(t *testing.T) {
	db, _ := testDB(t)
	cache := &sync.Map{}
	tables := map[string]bool{}
	for _, m := range phase3Models() {
		s, err := schema.Parse(m, cache, schema.NamingStrategy{})
		if err != nil {
			t.Fatalf("%T: %v", m, err)
		}
		tables[s.Table] = true
		var modelCols, modelPK []string
		for _, f := range s.Fields {
			if f.DBName == "" {
				continue
			}
			modelCols = append(modelCols, f.DBName)
			if f.PrimaryKey {
				modelPK = append(modelPK, f.DBName)
			}
		}
		var tableCols, tablePK []string
		rows, err := db.Query(`SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1`, s.Table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var c string
			_ = rows.Scan(&c)
			tableCols = append(tableCols, c)
		}
		rows.Close()
		rows, err = db.Query(`SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
		                       WHERE i.indrelid = to_regclass('public.' || $1) AND i.indisprimary`, s.Table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var c string
			_ = rows.Scan(&c)
			tablePK = append(tablePK, c)
		}
		rows.Close()
		sort.Strings(modelCols)
		sort.Strings(tableCols)
		sort.Strings(modelPK)
		sort.Strings(tablePK)
		if strings.Join(modelCols, ",") != strings.Join(tableCols, ",") {
			t.Errorf("%s: model columns\n  %v\ntable columns\n  %v", s.Table, modelCols, tableCols)
		}
		if strings.Join(modelPK, ",") != strings.Join(tablePK, ",") {
			t.Errorf("%s: model primary key %v, table primary key %v", s.Table, modelPK, tablePK)
		}
		// Generated columns must be read-only to GORM.
		for _, f := range s.Fields {
			var generated string
			_ = db.QueryRow(`SELECT is_generated FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`,
				s.Table, f.DBName).Scan(&generated)
			if generated == "ALWAYS" && (f.Creatable || f.Updatable) {
				t.Errorf("%s.%s is GENERATED ALWAYS but the model can write it", s.Table, f.DBName)
			}
		}
	}
	// Every Phase 3 TABLE has a model.
	for _, rel := range services.PolicySchemaRelations() {
		var kind string
		_ = db.QueryRow(`SELECT relkind::text FROM pg_class WHERE oid = to_regclass('public.' || $1)`, rel).Scan(&kind)
		if kind == "r" && !tables[rel] {
			t.Errorf("table %s has no model", rel)
		}
	}
	t.Logf("%d Phase 3 models match their tables", len(tables))
}
