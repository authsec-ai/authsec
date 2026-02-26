// AuthSec – merged monolith combining user-flow and webauthn-service.
//
// Previously these were two separate microservices:
//
//   - user-flow      (port 7468) – admin/enduser auth, RBAC, OIDC, SCIM, TOTP, CIBA
//   - webauthn-service (port 8080) – WebAuthn passkeys, TOTP setup, SMS MFA
//
// They are now a single process. The only architectural change is that the HTTP
// call webauthn-service previously made to user-flow's /uflow/webauthn/register
// is now an in-process call via the bridge package.
package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	authManagerConfig "github.com/authsec-ai/auth-manager/pkg/config"
	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/handlers"
	"github.com/authsec-ai/authsec/internal/clients/icp"
	session "github.com/authsec-ai/authsec/internal/session"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// @title           AuthSec API
// @version         5.0.0
// @description     Unified authentication and MFA service (user-flow + webauthn merged monolith)
// @contact.name   AuthSec AI
// @contact.url    https://authsec.ai
// @contact.email  support@authsec.ai
// @license.name  MIT
// @BasePath  /uflow
func main() {
	// Load .env file if present (optional, for development)
	godotenv.Load()

	// ─────────────────────────────────────────────────────────
	// Phase 1: user-flow initialisation
	// ─────────────────────────────────────────────────────────

	cfg := config.LoadConfig()

	monitoring.InitMetrics()

	// Initialise primary database (runs migrations)
	config.InitDatabaseWithoutGORM(cfg)

	// Initialise auth-manager configuration
	authManagerConfig.LoadConfig()
	authManagerConfig.SetDB(config.DB)
	authManagerConfig.InitTenantDBResolver(config.DB, nil)

	// Initialise Vault (optional; logs warning if not configured)
	config.InitVault(cfg)

	// Centralised token service (used by controllers and the bridge)
	tokenService, err := services.NewAuthManagerTokenService()
	if err != nil {
		monitoring.GetLogger().WithError(err).Fatal("Failed to initialize auth-manager token service")
	}
	config.TokenService = tokenService
	monitoring.GetLogger().Info("Auth-manager token service initialized")

	// Redis cache (optional)
	var cacheManager *monitoring.CacheManager
	if cfg.RedisURL != "" {
		cacheManager, err = monitoring.NewCacheManager(cfg.RedisURL)
		if err != nil {
			monitoring.GetLogger().WithError(err).Warn("Failed to initialize Redis cache, continuing without cache")
		} else {
			monitoring.GetLogger().Info("Redis cache initialized")
		}
	}

	// Audit logger
	auditLogger := monitoring.NewAuditLogger(config.DB)
	if err := auditLogger.InitAuditTable(); err != nil {
		monitoring.GetLogger().WithError(err).Fatal("Failed to initialize audit table")
	}

	config.CacheManager = cacheManager
	config.AuditLogger = auditLogger

	// ─────────────────────────────────────────────────────────
	// Phase 2: webauthn-service initialisation
	// ─────────────────────────────────────────────────────────

	// Validate WebAuthn-specific environment variables
	if err := validateWebAuthnEnvVars(); err != nil {
		log.Fatal("WebAuthn environment validation failed:", err)
	}

	rpName := getEnv("WEBAUTHN_RP_NAME", "AuthSec")
	rpIDRaw := getEnv("WEBAUTHN_RP_ID", "localhost")
	rpID := config.NormalizeRPID(rpIDRaw)
	origin := getEnv("WEBAUTHN_ORIGIN", "http://localhost:3000")

	webAuthn := config.SetupWebAuthn(rpName, rpID, origin)

	// PostgreSQL session manager for WebAuthn challenges (uses the same global DB)
	pgSessionManager := session.NewPostgreSQLSessionManager(config.DB, "")
	if err := pgSessionManager.CleanupExpiredSessions(); err != nil {
		log.Printf("Warning: failed to cleanup expired WebAuthn sessions: %v", err)
	}

	sessionAdapter := handlers.NewSessionManagerAdapter(pgSessionManager)

	webAuthnHandler := &handlers.WebAuthnHandler{
		WebAuthn:       webAuthn,
		SessionManager: sessionAdapter,
	}

	adminWebAuthnHandler := &handlers.AdminWebAuthnHandler{
		WebAuthn:       webAuthn,
		SessionManager: sessionAdapter,
		RPDisplayName:  rpName,
		RPID:           rpID,
		RPOrigins:      []string{origin},
	}

	endUserWebAuthnHandler := &handlers.EndUserWebAuthnHandler{
		WebAuthn:       webAuthn,
		SessionManager: sessionAdapter,
		RPDisplayName:  rpName,
		RPID:           rpID,
		RPOrigins:      []string{origin},
	}

	log.Printf("WebAuthn handlers initialized (RP Name: %s, RP ID: %s, Origin: %s)", rpName, rpID, origin)

	// ─────────────────────────────────────────────────────────
	// Phase 3: HTTP router
	// ─────────────────────────────────────────────────────────

	r := gin.New()

	// Metrics (must be first)
	r.Use(monitoring.Middleware())

	// CORS (shared config that handles both user-flow and webauthn origins)
	r.Use(setupCORS())

	// Core middleware
	r.Use(middlewares.RequestIDMiddleware())
	r.Use(middlewares.AuthLoggingMiddleware("authsec"))
	r.Use(middlewares.SecurityHeadersMiddleware())
	r.Use(middlewares.RecoveryMiddleware())
	r.Use(middlewares.TimeoutMiddleware(120 * time.Second))
	r.Use(middlewares.MennovRateLimitMiddleware())
	r.Use(gzip.Gzip(gzip.DefaultCompression))

	// Prometheus metrics endpoint
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// All routes (user-flow + webauthn)
	routes.SetupRoutes(r, webAuthnHandler, adminWebAuthnHandler, endUserWebAuthnHandler)

	// ─────────────────────────────────────────────────────────
	// Phase 4: background workers
	// ─────────────────────────────────────────────────────────

	// Audit log cleanup (runs daily, removes events older than 90 days)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := auditLogger.CleanupOldEvents(90 * 24 * time.Hour); err != nil {
				monitoring.GetLogger().WithError(err).Error("Failed to cleanup old audit events")
			}
		}
	}()

	// System metrics update (every 30 seconds)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			monitoring.UpdateSystemMetrics()
		}
	}()

	// PKI retry worker
	icpToken, err := services.GenerateOIDCServiceToken()
	if err != nil {
		log.Printf("Warning: failed to generate ICP service token for PKI retry worker: %v", err)
	} else {
		icpClient := icp.NewClient(cfg.ICPServiceURL, icpToken)
		icpService := services.NewICPProvisioningService(icpClient)
		pkiWorker := services.NewPKIRetryWorker(config.GetDatabase(), icpService, 5*time.Minute)
		pkiWorker.Start()
		log.Printf("PKI retry worker started")
	}

	// ─────────────────────────────────────────────────────────
	// Phase 5: start server
	// ─────────────────────────────────────────────────────────

	port := cfg.Port
	if port == "" {
		port = getEnv("PORT", "7468")
	}

	monitoring.GetLogger().
		WithField("port", port).
		WithField("webauthn_rp_id", rpID).
		Info("Starting AuthSec monolith")

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (previously in webauthn-service cmd/main.go)
// ─────────────────────────────────────────────────────────────────────────────

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func validateWebAuthnEnvVars() error {
	required := []string{"WEBAUTHN_RP_NAME", "WEBAUTHN_RP_ID", "WEBAUTHN_ORIGIN"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			return fmt.Errorf("required environment variable %s is not set", env)
		}
	}
	return nil
}

// setupCORS returns a CORS handler that covers both the user-flow and webauthn
// origin requirements: localhost, authsec.dev subdomains, explicit env-configured
// origins, and any verified custom domain from the tenant_domains table.
func setupCORS() gin.HandlerFunc {
	corsConfig := cors.DefaultConfig()

	originsEnv := getEnv("CORS_ALLOWED_ORIGINS", "")
	if originsEnv != "" {
		corsConfig.AllowOrigins = splitAndTrim(originsEnv)
		corsConfig.AllowWildcard = hasWildcard(corsConfig.AllowOrigins)
	} else {
		defaultOrigins, wildcard := buildDefaultOrigins()
		corsConfig.AllowOrigins = defaultOrigins
		corsConfig.AllowWildcard = wildcard
	}

	corsConfig.AllowOriginFunc = func(origin string) bool {
		if strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") {
			return true
		}
		if strings.HasSuffix(origin, ".authsec.dev") || origin == "https://authsec.dev" || origin == "http://authsec.dev" {
			return true
		}
		for _, allowedOrigin := range corsConfig.AllowOrigins {
			if origin == allowedOrigin {
				return true
			}
			if strings.Contains(allowedOrigin, "*") {
				pattern := strings.ReplaceAll(allowedOrigin, "*", ".*")
				matched, _ := regexp.MatchString("^"+pattern+"$", origin)
				if matched {
					return true
				}
			}
		}
		return isVerifiedTenantDomain(origin)
	}

	if methods := getEnv("CORS_ALLOWED_METHODS", ""); methods != "" {
		corsConfig.AllowMethods = splitAndTrim(methods)
	} else {
		corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}

	if headers := getEnv("CORS_ALLOWED_HEADERS", ""); headers != "" {
		corsConfig.AllowHeaders = splitAndTrim(headers)
	} else {
		corsConfig.AllowHeaders = []string{
			"Origin", "Content-Length", "Content-Type", "Authorization",
			"X-Requested-With", "Accept", "Accept-Encoding", "Accept-Language",
		}
	}

	corsConfig.ExposeHeaders = []string{"X-Request-ID", "Content-Length"}
	corsConfig.AllowCredentials = true
	corsConfig.MaxAge = 12 * 3600

	return cors.New(corsConfig)
}

func buildDefaultOrigins() ([]string, bool) {
	originValue := strings.TrimSpace(getEnv("WEBAUTHN_ORIGIN", ""))
	if originValue == "" {
		return []string{"http://localhost:3000"}, false
	}
	parsed, err := url.Parse(originValue)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		origins := splitAndTrim(originValue)
		return origins, hasWildcard(origins)
	}
	baseOrigin := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	origins := []string{baseOrigin}
	hostWithoutPort := parsed.Host
	if h, _, err := net.SplitHostPort(parsed.Host); err == nil {
		hostWithoutPort = h
	}
	wildcardAdded := false
	if isWildcardCandidate(hostWithoutPort) {
		wildcardOrigin := fmt.Sprintf("%s://*.%s", parsed.Scheme, hostWithoutPort)
		origins = append(origins, wildcardOrigin)
		wildcardAdded = true
	}
	return uniqueStrings(origins), wildcardAdded
}

func splitAndTrim(csv string) []string {
	values := strings.Split(csv, ",")
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

func hasWildcard(values []string) bool {
	for _, v := range values {
		if strings.Contains(v, "*") {
			return true
		}
	}
	return false
}

func isWildcardCandidate(host string) bool {
	if host == "" || host == "localhost" {
		return false
	}
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.Contains(host, ".")
}

// isVerifiedTenantDomain checks the tenant_domains table to allow CORS for
// verified custom domains. Uses the same global DB as the rest of the service.
func isVerifiedTenantDomain(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	domain := parsed.Host
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	if strings.HasSuffix(domain, ".authsec.dev") || domain == "authsec.dev" {
		return false
	}
	if config.DB == nil {
		return false
	}
	var count int64
	err = config.DB.Table("tenant_domains").
		Where("domain = ? AND is_verified = true", domain).
		Count(&count).Error
	if err != nil {
		log.Printf("CORS: Error querying tenant_domains for domain %s: %v", domain, err)
		return false
	}
	return count > 0
}
