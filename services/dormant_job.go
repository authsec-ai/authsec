package services

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/database"
	_ "github.com/lib/pq"
	"github.com/robfig/cron/v3"
)

// DormantWorker runs a nightly job that moves inactive users to the SendGrid dormant list.
type DormantWorker struct {
	masterDB *database.DBConnection
	sg       *SendGridService
	cfg      dormantCfg
	cron     *cron.Cron
}

// dormantCfg holds the config values the worker needs, extracted at construction time.
type dormantCfg struct {
	dbHost, dbUser, dbPassword, dbPort string
	dbSSLMode                          string
	listNewSignups, listTrialUsers     string
	listLeads, listDormant             string
	fieldSegment                       string
}

// NewDormantWorker creates a DormantWorker.
// masterDB is the authsec master database (holds the tenants table).
// sg must not be nil.
func NewDormantWorker(
	masterDB *database.DBConnection,
	sg *SendGridService,
	dbHost, dbUser, dbPassword, dbPort, dbSSLMode string,
	listNewSignups, listTrialUsers, listLeads, listDormant, fieldSegment string,
) *DormantWorker {
	return &DormantWorker{
		masterDB: masterDB,
		sg:       sg,
		cfg: dormantCfg{
			dbHost: dbHost, dbUser: dbUser, dbPassword: dbPassword, dbPort: dbPort, dbSSLMode: dbSSLMode,
			listNewSignups: listNewSignups, listTrialUsers: listTrialUsers,
			listLeads: listLeads, listDormant: listDormant,
			fieldSegment: fieldSegment,
		},
	}
}

// Start registers the nightly cron (02:00 UTC) and begins the scheduler.
// The returned stop function should be called on server shutdown.
func (w *DormantWorker) Start() (stop func()) {
	w.cron = cron.New(cron.WithLocation(time.UTC))
	_, err := w.cron.AddFunc("0 2 * * *", func() {
		log.Println("dormant-worker: starting nightly run")
		w.run()
		log.Println("dormant-worker: nightly run complete")
	})
	if err != nil {
		log.Printf("dormant-worker: failed to schedule cron: %v", err)
		return func() {}
	}
	w.cron.Start()
	log.Println("dormant-worker: cron scheduler started (runs at 02:00 UTC)")
	return func() { <-w.cron.Stop().Done() }
}

// run executes one dormant sweep across all tenant databases.
func (w *DormantWorker) run() {
	tenants, err := w.listTenants()
	if err != nil {
		log.Printf("dormant-worker: failed to list tenants: %v", err)
		return
	}

	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	cooloff := time.Now().UTC().Add(-90 * 24 * time.Hour)

	for _, t := range tenants {
		if t.tenantDB == "" {
			continue
		}
		if err := w.processTenant(t, cutoff, cooloff); err != nil {
			log.Printf("dormant-worker: tenant %s: %v", t.tenantID, err)
		}
	}
}

type tenantRow struct {
	tenantID string
	tenantDB string
}

func (w *DormantWorker) listTenants() ([]tenantRow, error) {
	rows, err := w.masterDB.Query("SELECT tenant_id, COALESCE(tenant_db, '') FROM tenants WHERE status != 'deleted'")
	if err != nil {
		return nil, fmt.Errorf("query tenants: %w", err)
	}
	defer rows.Close()

	var tenants []tenantRow
	for rows.Next() {
		var t tenantRow
		if err := rows.Scan(&t.tenantID, &t.tenantDB); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}

func (w *DormantWorker) processTenant(t tenantRow, cutoff, cooloff time.Time) error {
	sslMode := w.cfg.dbSSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		w.cfg.dbHost, w.cfg.dbUser, w.cfg.dbPassword, t.tenantDB, w.cfg.dbPort, sslMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open tenant db %s: %w", t.tenantDB, err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping tenant db %s: %w", t.tenantDB, err)
	}

	users, err := w.queryDormantUsers(db, cutoff, cooloff)
	if err != nil {
		return fmt.Errorf("query dormant users: %w", err)
	}

	for _, u := range users {
		w.enrollDormant(db, u)
	}
	return nil
}

type dormantUser struct {
	email     string
	firstName string
}

func (w *DormantWorker) queryDormantUsers(db *sql.DB, cutoff, cooloff time.Time) ([]dormantUser, error) {
	query := `
		SELECT COALESCE(email, ''), COALESCE(name, '')
		FROM users
		WHERE (last_login IS NULL OR last_login < $1)
		  AND active = true
		  AND (
		        dormant_enrolled = false
		        OR (dormant_enrolled = true AND dormant_enrolled_at < $2)
		      )
	`
	rows, err := db.Query(query, cutoff, cooloff)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var users []dormantUser
	for rows.Next() {
		var u dormantUser
		if err := rows.Scan(&u.email, &u.firstName); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if u.email != "" {
			users = append(users, u)
		}
	}
	return users, rows.Err()
}

func (w *DormantWorker) enrollDormant(db *sql.DB, u dormantUser) {
	cfg := w.cfg

	// Remove from active nurture lists first.
	if err := w.sg.RemoveFromLists(u.email, []string{cfg.listNewSignups, cfg.listTrialUsers, cfg.listLeads}); err != nil {
		log.Printf("dormant-worker: remove from active lists failed for %s: %v", u.email, err)
	}

	// Add to dormant re-engagement sequence.
	jobID, err := w.sg.UpsertContact(u.email, u.firstName, cfg.listDormant, map[string]string{
		cfg.fieldSegment: "dormant",
	})
	if err != nil {
		log.Printf("dormant-worker: enroll in dormant list failed for %s: %v", u.email, err)
		return
	}
	log.Printf(`{"sendgrid_job_id":%q,"list":"seg-dormant","contact":%q}`, jobID, u.email)

	// Mark enrolled so the job doesn't re-enroll on the next run.
	if _, err := db.Exec(
		`UPDATE users SET dormant_enrolled = true, dormant_enrolled_at = NOW(), updated_at = NOW() WHERE LOWER(email) = LOWER($1)`,
		u.email,
	); err != nil {
		log.Printf("dormant-worker: mark enrolled failed for %s: %v", u.email, err)
	}
}
