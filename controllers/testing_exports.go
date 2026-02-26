package controllers

import (
	"net/http"
	"time"

	sharedmodels "github.com/authsec-ai/sharedmodels"
	"github.com/authsec-ai/authsec/models"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// BuildAdminUserResponseForTest exposes buildAdminUserResponse for tests in other packages.
func BuildAdminUserResponseForTest(user models.AdminUser) (map[string]interface{}, error) {
	return buildAdminUserResponse(user)
}

// IsAdminUserInviteForTest exposes isAdminUserInvite for tests in other packages.
func IsAdminUserInviteForTest(user models.AdminUser) bool {
	return isAdminUserInvite(user)
}

// IsPendingAdminInviteForTest exposes isPendingAdminInvite for tests in other packages.
func IsPendingAdminInviteForTest(user models.AdminUser) bool {
	return isPendingAdminInvite(user)
}

// JWTDefaultSecretForTest returns the default JWT secret used by controllers.
func JWTDefaultSecretForTest() []byte {
	return jwtDefaultSecret
}

// GenerateEndUserJWTTokenForTest wraps generateJWTToken for tests outside the controllers package.
func (euac *EndUserAuthController) GenerateEndUserJWTTokenForTest(tenantID, clientID, emailID, tenantDomain string, userID *uuid.UUID, tenantDB interface{}) (string, error) {
	return euac.generateJWTToken(tenantID, clientID, emailID, tenantDomain, userID, tenantDB)
}

// ConnectToADForTest exposes connectToAD for external tests.
func (asc *ADSyncController) ConnectToADForTest(config models.ADSyncConfig) (*ldap.Conn, error) {
	return asc.connectToAD(config)
}

// FetchADUsersForTest exposes fetchADUsers for external tests.
func (asc *ADSyncController) FetchADUsersForTest(config models.ADSyncConfig) ([]models.ADUser, error) {
	return asc.fetchADUsers(config)
}

// SyncUserToDatabaseForTest exposes syncUserToDatabase for external tests.
func (asc *ADSyncController) SyncUserToDatabaseForTest(tenantDB *gorm.DB, adUser models.ADUser, tenantID, clientID, projectID string) error {
	return asc.syncUserToDatabase(tenantDB, adUser, tenantID, clientID, projectID)
}

// SyncAgentUserToDatabaseForTest exposes syncAgentUserToDatabase for external tests.
func (asc *ADSyncController) SyncAgentUserToDatabaseForTest(tenantDB *gorm.DB, agentUser models.AgentUserData, tenantID, projectID, clientID string) error {
	return asc.syncAgentUserToDatabase(tenantDB, agentUser, tenantID, projectID, clientID)
}

// MapLDAPEntryToUserForTest exposes mapLDAPEntryToUser for external tests.
func (asc *ADSyncController) MapLDAPEntryToUserForTest(entry *ldap.Entry) models.ADUser {
	return asc.mapLDAPEntryToUser(entry)
}

// SetTenantConnectionProviderForTest replaces tenantConnectionProvider and returns the previous provider.
func SetTenantConnectionProviderForTest(provider func(interface{}, *string, *string) (*gorm.DB, error)) func(interface{}, *string, *string) (*gorm.DB, error) {
	previous := tenantConnectionProvider
	tenantConnectionProvider = provider
	return previous
}

// SetTimeNowForTest replaces timeNow and returns the previous function.
func SetTimeNowForTest(now func() time.Time) func() time.Time {
	previous := timeNow
	timeNow = now
	return previous
}

// ResolveEndUserLookupForTest exposes resolveEndUserLookup for tests in other packages.
func ResolveEndUserLookupForTest(identifier string, clientID string) (bool, uuid.UUID, uuid.UUID, string, error) {
	return resolveEndUserLookup(identifier, clientID)
}

// ValidateOIDCTokenForTest exposes validateOIDCToken for tests.
func (euc *EndUserController) ValidateOIDCTokenForTest(token string) (*sharedmodels.Introspection, error) {
	return euc.validateOIDCToken(token)
}

// TenantMappingForTest exposes tenantMapping for tests.
func (euc *EndUserController) TenantMappingForTest(clientID uuid.UUID) (uuid.UUID, error) {
	return euc.tenantMapping(clientID)
}

// GenerateAndSendCustomPasswordResetOTPForTest exposes generateAndSendCustomPasswordResetOTP for tests.
func (euc *EndUserController) GenerateAndSendCustomPasswordResetOTPForTest(email string) error {
	return euc.generateAndSendCustomPasswordResetOTP(email)
}

// GenerateAndSendOTPForTest exposes generateAndSendOTP for tests.
func (uc *UserController) GenerateAndSendOTPForTest(email string) error {
	return uc.generateAndSendOTP(email)
}

// NewEntraIDServiceForTest exposes newEntraIDService for tests.
func (ec *EntraIDController) NewEntraIDServiceForTest(config *EntraIDConfig) *EntraIDService {
	return ec.newEntraIDService(config)
}

// NewEntraIDServiceWithClientForTest constructs an EntraIDService with test dependencies.
func NewEntraIDServiceWithClientForTest(config *EntraIDConfig, client *http.Client, token string) *EntraIDService {
	return &EntraIDService{
		config:      config,
		client:      client,
		accessToken: token,
	}
}

// AuthenticateForTest exposes authenticate for tests.
func (es *EntraIDService) AuthenticateForTest() error {
	return es.authenticate()
}

// FetchEntraIDUsersForTest exposes fetchEntraIDUsers for tests.
func (es *EntraIDService) FetchEntraIDUsersForTest() ([]EntraIDUser, error) {
	return es.fetchEntraIDUsers()
}

// FetchUsersWithLimitForTest exposes fetchUsersWithLimit for tests.
func (es *EntraIDService) FetchUsersWithLimitForTest(limit int) ([]GraphUser, error) {
	return es.fetchUsersWithLimit(limit)
}

// CheckPermissionsForTest exposes checkPermissions for tests.
func (es *EntraIDService) CheckPermissionsForTest() (map[string]interface{}, error) {
	return es.checkPermissions()
}

// ConfigForTest returns the EntraIDService config for assertions.
func (es *EntraIDService) ConfigForTest() *EntraIDConfig {
	return es.config
}

// ClientForTest returns the HTTP client used by the EntraIDService.
func (es *EntraIDService) ClientForTest() *http.Client {
	return es.client
}

// AccessTokenForTest returns the stored access token.
func (es *EntraIDService) AccessTokenForTest() string {
	return es.accessToken
}

// TokenExpiryForTest returns the token expiry time.
func (es *EntraIDService) TokenExpiryForTest() time.Time {
	return es.tokenExpiry
}
