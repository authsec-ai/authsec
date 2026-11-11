package services

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	repositories "github.com/authsec-ai/authsec/repository"
)

// Schema gates of the agent runtime visibility parts. Like every IGA part
// they serve once their own schema verifies and fail closed, with the reason
// in /api/iga/v1/capabilities, until then; there is no switch. A verification
// is cached and, until it passes, retried at most once a minute.

const (
	// AgentAlertsSchemaHead is the migration alerts need.
	AgentAlertsSchemaHead = "150"
	// AgentRuntimeSchemaHead names the migrations the runtime (inference,
	// suggestions, findings, event stream, CloudTrail cursor) needs.
	AgentRuntimeSchemaHead = "147, 148, 149, 160, 161"

	// GovCodeAgentAlertsUnavailable and GovCodeAgentRuntimeUnavailable are the
	// 503 codes of the alert routes and the runtime routes.
	GovCodeAgentAlertsUnavailable  = "agent_alerts_unavailable"
	GovCodeAgentRuntimeUnavailable = "agent_runtime_unavailable"
)

var agentAlertsSchemaRelations = []string{"agent_alert", "agent_alert_siem_endpoint", "agent_alert_delivery",
	"agent_alert_baseline", "agent_alert_setting", "agent_alert_event_seen"}

var agentRuntimeSchemaRelations = []string{"cloud_trail_cursor", "cloud_trail_seen_event", "agent_suggestion", "agent_finding",
	"agent_event_stream", "agent_event_seen"}

type agentSchemaGate struct {
	mu        sync.Mutex
	head      string
	relations []string
	columns   [][2]string // {table, column} a relation check cannot prove
	ok        bool
	reason    string
	at        time.Time
	logged    string // the reason last logged, so a wait logs once
}

var (
	agentAlertsGate  = &agentSchemaGate{head: AgentAlertsSchemaHead, relations: agentAlertsSchemaRelations}
	agentRuntimeGate = &agentSchemaGate{head: AgentRuntimeSchemaHead, relations: agentRuntimeSchemaRelations,
		columns: [][2]string{{"agent_event_seen", "dispatched_at"}}}
)

func (g *agentSchemaGate) verify(db *gorm.DB) error {
	var missing []string
	for _, rel := range g.relations {
		ok, err := repositories.HasRelation(db, rel)
		if err != nil {
			return fmt.Errorf("schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, rel)
		}
	}
	for _, c := range g.columns {
		ok, err := repositories.HasColumn(db, c[0], c[1])
		if err != nil {
			return fmt.Errorf("schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, c[0]+"."+c[1])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("needs migration %s; missing: %s", g.head, strings.Join(missing, ", "))
	}
	return nil
}

func (g *agentSchemaGate) status(db *gorm.DB) (bool, string) {
	if db == nil {
		return false, "no database"
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.ok && time.Since(g.at) > time.Minute {
		g.at = time.Now()
		if err := g.verify(db); err != nil {
			g.reason = err.Error()
		} else {
			g.ok, g.reason = true, ""
		}
	}
	if !g.ok && g.reason == "" {
		return false, "the schema (migration " + g.head + ") has not been verified yet"
	}
	return g.ok, g.reason
}

// logWait logs the unavailable reason once per distinct reason.
func (g *agentSchemaGate) logWait(what, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.logged != reason {
		g.logged = reason
		log.Printf("[agent-runtime] %s skipped until its schema verifies: %s", what, reason)
	}
}

// AgentAlertsStatus is whether alerts can run (migration 150's tables).
func AgentAlertsStatus(db *gorm.DB) (bool, string) { return agentAlertsGate.status(db) }

// AgentRuntimeStatus is whether the runtime routes can run (147, 148, 149).
func AgentRuntimeStatus(db *gorm.DB) (bool, string) { return agentRuntimeGate.status(db) }

// AgentAlertsCapabilities is /capabilities' agent_alerts block:
// {"available": bool, "reason": string|null}.
func AgentAlertsCapabilities(db *gorm.DB) map[string]any {
	ok, reason := AgentAlertsStatus(db)
	return map[string]any{"available": ok, "reason": nullable(reason)}
}

// AgentRuntimeCapabilities is /capabilities' agent_runtime block, same shape.
func AgentRuntimeCapabilities(db *gorm.DB) map[string]any {
	ok, reason := AgentRuntimeStatus(db)
	return map[string]any{"available": ok, "reason": nullable(reason)}
}

// RequireAgentAlerts is nil while alerts can run, else the 503.
func RequireAgentAlerts(db *gorm.DB) error {
	if ok, reason := AgentAlertsStatus(db); !ok {
		return govErr(http.StatusServiceUnavailable, GovCodeAgentAlertsUnavailable, "Agent runtime alerts are not available on this server.",
			map[string]any{"reason": reason})
	}
	return nil
}

// RequireAgentRuntime is nil while the runtime routes can run, else the 503.
func RequireAgentRuntime(db *gorm.DB) error {
	if ok, reason := AgentRuntimeStatus(db); !ok {
		return govErr(http.StatusServiceUnavailable, GovCodeAgentRuntimeUnavailable, "Agent runtime visibility is not available on this server.",
			map[string]any{"reason": reason})
	}
	return nil
}
