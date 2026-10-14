package middleware

import (
	"crypto/x509"

	"github.com/gin-gonic/gin"
)

// Context keys set by the certificate middleware. The request's workspace is
// not among them: it is the tenancy context (tenancy.Workspace(c)), set
// only from a verified credential.
const (
	SpireSpiffeIDKey   = "spire_spiffe_id"
	SpireIsAgentKey    = "spire_is_agent"
	SpireClientCertKey = "spire_client_cert"
	SpireAgentIDKey    = "spire_agent_id"
)

// GetSpireSpiffeID returns the authenticated SPIFFE ID.
func GetSpireSpiffeID(c *gin.Context) (string, bool) {
	s, ok := c.Get(SpireSpiffeIDKey)
	if !ok {
		return "", false
	}
	v, ok := s.(string)
	return v, ok && v != ""
}

// GetSpireIsAgent reports whether the caller authenticated as an agent.
func GetSpireIsAgent(c *gin.Context) (bool, bool) {
	val, exists := c.Get(SpireIsAgentKey)
	if !exists {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}

// GetSpireClientCert returns the verified client certificate.
func GetSpireClientCert(c *gin.Context) (*x509.Certificate, bool) {
	val, exists := c.Get(SpireClientCertKey)
	if !exists {
		return nil, false
	}
	cert, ok := val.(*x509.Certificate)
	return cert, ok
}

// GetSpireAgentID returns the authenticated agent's id (spire_agents.id).
func GetSpireAgentID(c *gin.Context) (string, bool) {
	val, exists := c.Get(SpireAgentIDKey)
	if !exists {
		return "", false
	}
	s, ok := val.(string)
	return s, ok && s != ""
}
