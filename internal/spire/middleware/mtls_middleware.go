package middleware

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// MTLSMiddleware handles mTLS authentication and tenant extraction from client certificates.
type MTLSMiddleware struct {
	logger        *logrus.Logger
	devModeBypass bool
}

// NewMTLSMiddleware creates a new mTLS middleware.
// Dev mode bypass is enabled when ENVIRONMENT is "development" or "dev" and TLS_SERVER_CERT_PATH is not set.
func NewMTLSMiddleware(logger *logrus.Logger) *MTLSMiddleware {
	devMode := os.Getenv("ENVIRONMENT") == "development" || os.Getenv("ENVIRONMENT") == "dev"
	tlsConfigured := os.Getenv("TLS_SERVER_CERT_PATH") != ""

	return &MTLSMiddleware{
		logger:        logger,
		devModeBypass: devMode && !tlsConfigured,
	}
}

// Authenticate returns a Gin middleware that validates client certificates via mTLS.
func (m *MTLSMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Development mode bypass: extract tenant from header
		if m.devModeBypass && c.Request.TLS == nil {
			m.logger.Warn("DEV MODE: Bypassing mTLS authentication (DO NOT USE IN PRODUCTION)")

			workspaceID := c.GetHeader("X-Tenant-ID")
			if workspaceID == "" {
				workspaceID = "4e615215-66b4-4414-bb39-4e0c6daa8f8b" // Default dev tenant
			}

			c.Set(SpireWorkspaceIDKey, workspaceID)
			c.Set(SpireSpiffeIDKey, "spiffe://"+workspaceID+"/dev/admin")
			c.Set(SpireIsAgentKey, false)

			m.logger.WithField("workspace_id", workspaceID).Debug("Dev mode authentication bypassed")
			c.Next()
			return
		}

		// Verify TLS connection exists
		if c.Request.TLS == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "UNAUTHORIZED",
					"message": "TLS connection required",
				},
			})
			return
		}

		// Verify client certificate present
		if len(c.Request.TLS.PeerCertificates) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "UNAUTHORIZED",
					"message": "Client certificate required",
				},
			})
			return
		}

		cert := c.Request.TLS.PeerCertificates[0]

		// Extract SPIFFE ID from URI SAN
		spiffeID, err := extractSpiffeID(cert)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "UNAUTHORIZED",
					"message": "SPIFFE ID not found in certificate",
				},
			})
			return
		}

		// Parse SPIFFE ID to extract tenant and type
		workspaceID, isAgent, err := parseSpiffeID(spiffeID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": gin.H{
					"code":    "UNAUTHORIZED",
					"message": "Invalid SPIFFE ID format",
				},
			})
			return
		}

		// Set Gin context values
		c.Set(SpireWorkspaceIDKey, workspaceID)
		c.Set(SpireSpiffeIDKey, spiffeID)
		c.Set(SpireIsAgentKey, isAgent)
		c.Set(SpireClientCertKey, cert)

		m.logger.WithFields(logrus.Fields{
			"spiffe_id": spiffeID,
			"workspace_id": workspaceID,
			"is_agent":  isAgent,
		}).Debug("mTLS authenticated")

		c.Next()
	}
}

// extractSpiffeID extracts the SPIFFE ID from certificate URI SANs.
func extractSpiffeID(cert *x509.Certificate) (string, error) {
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), "spiffe://") {
			return uri.String(), nil
		}
	}
	return "", &spireError{Code: "UNAUTHORIZED", Message: "No SPIFFE ID found in certificate URI SANs"}
}

// parseSpiffeID parses a SPIFFE ID to extract tenant ID and determine if the identity is an agent.
// Format: spiffe://tenant-id/agent/node-id (for agents)
//
//	spiffe://tenant-id/ns/namespace/sa/serviceaccount (for workloads)
func parseSpiffeID(spiffeID string) (workspaceID string, isAgent bool, err error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return "", false, err
	}

	if u.Scheme != "spiffe" {
		return "", false, &spireError{Code: "BAD_REQUEST", Message: "Not a SPIFFE ID"}
	}

	workspaceID = u.Host
	if workspaceID == "" {
		return "", false, &spireError{Code: "BAD_REQUEST", Message: "Tenant ID missing in SPIFFE ID"}
	}

	path := strings.Trim(u.Path, "/")
	parts := strings.Split(path, "/")

	// Check if this is an agent SVID
	if len(parts) >= 1 && parts[0] == "agent" {
		isAgent = true
	}

	return workspaceID, isAgent, nil
}

// spireError is a simple error type used within the middleware package.
type spireError struct {
	Code    string
	Message string
}

func (e *spireError) Error() string {
	return e.Code + ": " + e.Message
}
