package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/monitoring"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

// AuthManagerTokenService interface for token generation using auth-manager patterns
// This avoids import cycles while providing type-safe token generation
type AuthManagerTokenService interface {
	GenerateAdminToken(adminUserID uuid.UUID, email string, projectID uuid.UUID, tenantID *uuid.UUID, tenantDomain string, roles []string) (string, error)
	GenerateTenantUserToken(userID uuid.UUID, tenantID uuid.UUID, projectID uuid.UUID, email string, expiresIn time.Duration) (string, error)
	GenerateEndUserToken(userID uuid.UUID, tenantID string, clientID string, email string, scopes []string, expiresIn time.Duration) (string, error)
	GenerateVoiceAuthToken(userID uuid.UUID, tenantID uuid.UUID, email string, scopes []string, expiresIn time.Duration) (string, error)
	GenerateDeviceAuthToken(userID uuid.UUID, tenantID uuid.UUID, email string, scopes []string, expiresIn time.Duration) (string, error)
	GenerateCIBAToken(userID uuid.UUID, tenantID uuid.UUID, email string, scopes []string, expiresIn time.Duration) (string, error)
	GenerateTenantCIBAToken(userID uuid.UUID, tenantID uuid.UUID, clientID uuid.UUID, email string, scopes []string, expiresIn time.Duration) (string, error)
	GenerateTOTPToken(userID uuid.UUID, tenantID uuid.UUID, email string, expiresIn time.Duration) (string, error)
}

type Config struct {
	Port               string
	DBName             string
	DBUser             string
	DBPassword         string
	DBHost             string
	DBPort             string
	DBSchema           string
	DatabaseURL        string
	JWTDefSecret       string
	JWTSdkSecret       string
	OOCManagerURL      string
	VaultAddr          string
	VaultToken         string
	HydraAdminURL      string
	SMTPHost           string
	SMTPPort           string
	SMTPUser           string
	SMTPPassword       string
	TenantDomainSuffix string
	CorsAllowOrigin    string // Added for CORS configuration
	RedisURL           string // Added for Redis caching
	ICPServiceURL      string // ICP service URL for PKI provisioning
	BaseURL            string // Base URL for callbacks (e.g., https://app.authsec.dev)

	// OIDC Provider credentials (fallback when Vault is not available)
	GoogleClientSecret    string
	GitHubClientSecret    string
	MicrosoftClientSecret string

	// HubSpot integration
	HubSpotAccessToken string
}

var (
	AppConfig    *Config
	CacheManager *monitoring.CacheManager
	AuditLogger  *monitoring.AuditLogger
	TokenService AuthManagerTokenService // Global token service using auth-manager patterns
	
	// Redis client singleton
	redisClient *redis.Client
	redisOnce   sync.Once
)

func LoadConfig() *Config {
	// Return existing config if already loaded
	if AppConfig != nil {
		return AppConfig
	}

	// Load individual database variables
	dbName := getEnv("DB_NAME", "kloudone_db")
	dbUser := getEnv("DB_USER", "asiffinal")
	dbPassword := getEnv("DB_PASSWORD", "test1")
	dbHost := getEnv("DB_HOST", "postgres")
	dbPort := getEnv("DB_PORT", "5432")
	dbSchema := getEnv("DB_SCHEMA", "public")

	// Construct DatabaseURL
	databaseURL := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable search_path=%s",
		dbHost, dbUser, dbPassword, dbName, dbPort, dbSchema,
	)

	err := os.Setenv("DATABASE_URL", databaseURL)
	if err != nil {
		fmt.Println("Error setting env var:", err)
	}

	// Load other configuration variables
	port := getEnv("PORT", "7468")
	jwtSdkSecret := getEnv("JWT_SDK_SECRET", "authsecai")
	jwtDefSecret := getEnv("JWT_DEF_SECRET", "authsecai")
	oocManagerURL := getEnv("OOC_MANAGER_URL", "http://localhost:7467")

	vaultAddr := getEnv("VAULT_ADDR", "http://localhost:8200")
	vaultToken := getEnv("VAULT_TOKEN", "")
	hydraAdminURL := getEnv("HYDRA_ADMIN_URL", "http://localhost:4445")

	corsAllowOrigin := getEnv("CORS_ALLOW_ORIGIN", "https://*.app.authsec.dev,https://app.authsec.dev,https://*.authsec.dev,https://authsec.dev,https://*.authsec.ai,https://200xx.app.authsec.dev")

	// Load Tenant Domain Suffix
	tenantDomainSuffix := getEnv("TENANT_DOMAIN_SUFFIX", "app.authsec.ai")

	// Load Redis configuration
	redisURL := getEnv("REDIS_URL", "")

	// Load ICP service configuration
	icpServiceURL := getEnv("ICP_SERVICE_URL", "http://localhost:7001")

	// Load SMTP configuration
	smtpHost := getEnv("SMTP_HOST", "")
	smtpPort := getEnv("SMTP_PORT", "")
	smtpUser := getEnv("SMTP_USER", "")
	smtpPassword := getEnv("SMTP_PASSWORD", "")

	// Load Base URL for OIDC callbacks
	baseURL := getEnv("BASE_URL", "https://app.authsec.dev")

	// Load OIDC provider credentials (fallback for when Vault is not available)
	googleClientSecret := getEnv("GOOGLE_CLIENT_SECRET", "")
	githubClientSecret := getEnv("GITHUB_CLIENT_SECRET", "")
	microsoftClientSecret := getEnv("MICROSOFT_CLIENT_SECRET", "")

	// Load HubSpot configuration
	hubSpotAccessToken := getEnv("HUBSPOT_ACCESS_TOKEN", "")

	// Validate critical variables
	if dbName == "" || dbUser == "" || dbHost == "" || dbPort == "" {
		log.Fatal("DB_NAME, DB_USER, DB_HOST, and DB_PORT are required")
	}
	if port == "" {
		log.Fatal("PORT is required")
	}

	AppConfig = &Config{
		Port:                  port,
		DBName:                dbName,
		DBUser:                dbUser,
		DBPassword:            dbPassword,
		DBHost:                dbHost,
		DBPort:                dbPort,
		DBSchema:              dbSchema,
		DatabaseURL:           databaseURL,
		JWTDefSecret:          jwtDefSecret,
		JWTSdkSecret:          jwtSdkSecret,
		OOCManagerURL:         oocManagerURL,
		VaultAddr:             vaultAddr,
		VaultToken:            vaultToken,
		HydraAdminURL:         hydraAdminURL,
		SMTPHost:              smtpHost,
		SMTPPort:              smtpPort,
		SMTPUser:              smtpUser,
		SMTPPassword:          smtpPassword,
		TenantDomainSuffix:    tenantDomainSuffix,
		CorsAllowOrigin:       corsAllowOrigin,
		RedisURL:              redisURL,
		ICPServiceURL:         icpServiceURL,
		BaseURL:               baseURL,
		GoogleClientSecret:    googleClientSecret,
		GitHubClientSecret:    githubClientSecret,
		MicrosoftClientSecret: microsoftClientSecret,
		HubSpotAccessToken:    hubSpotAccessToken,
	}

	return AppConfig
}

// ADD THIS: New getter function
func GetConfig() *Config {
	if AppConfig == nil {
		log.Fatal("Configuration not loaded. Call LoadConfig() first.")
	}
	return AppConfig
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		log.Printf("Loaded %s: %s", key, value)
		return value
	}
	log.Printf("Using fallback for %s: %s", key, fallback)
	return fallback
}

// GetEnv is a public wrapper for getEnv
func GetEnv(key, fallback string) string {
	return getEnv(key, fallback)
}

// GetRedisClient returns a singleton Redis client instance
func GetRedisClient() *redis.Client {
	redisOnce.Do(func() {
		if AppConfig == nil {
			log.Println("Warning: Config not loaded, Redis client may use default configuration")
		}
		
		// Get Redis configuration
		redisURL := ""
		if AppConfig != nil {
			redisURL = AppConfig.RedisURL
		}
		if redisURL == "" {
			redisURL = getEnv("REDIS_URL", "redis://localhost:6379")
		}
		
		// Parse Redis URL or use default options
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			// Fallback to default Redis configuration
			log.Printf("Failed to parse Redis URL, using default: %v", err)
			opt = &redis.Options{
				Addr:     "localhost:6379",
				Password: "",
				DB:       0,
			}
		}
		
		redisClient = redis.NewClient(opt)
		
		// Test connection
		ctx := context.Background()
		_, err = redisClient.Ping(ctx).Result()
		if err != nil {
			log.Printf("Warning: Failed to connect to Redis: %v", err)
			log.Println("Token revocation and refresh features will not be available")
		} else {
			log.Println("Successfully connected to Redis")
		}
	})
	
	return redisClient
}

