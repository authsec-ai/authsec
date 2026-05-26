package sharedmodels

// HealthResponse represents the health check response
type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

// ProfileResponse represents the user profile response
type ProfileResponse struct {
	WorkspaceID  string      `json:"workspace_id"`
	ProjectID string      `json:"project_id"`
	ClientID  string      `json:"client_id"`
	EmailID   string      `json:"email_id"`
	Scopes    interface{} `json:"scopes"`
	Roles     interface{} `json:"roles"`
	Groups    interface{} `json:"groups"`
	Resources interface{} `json:"resources"`
	TokenType interface{} `json:"token_type"`
}

// ValidationResponse represents validation endpoint responses
type ValidationResponse struct {
	Message   string      `json:"message"`
	Service   string      `json:"service,omitempty"`
	Purpose   string      `json:"purpose,omitempty"`
	WorkspaceID  string      `json:"workspace_id,omitempty"`
	ProjectID string      `json:"project_id,omitempty"`
	ClientID  string      `json:"client_id,omitempty"`
	Scopes    interface{} `json:"scopes,omitempty"`
	Roles     interface{} `json:"roles,omitempty"`
	Resources interface{} `json:"resources,omitempty"`
}

// ScopeValidationResponse represents scope validation response
type ScopeValidationResponse struct {
	Message       string      `json:"message"`
	RequiredScope string      `json:"required_scope"`
	UserScopes    interface{} `json:"user_scopes"`
}

// ResourceValidationResponse represents resource validation response
type ResourceValidationResponse struct {
	Message          string      `json:"message"`
	RequiredResource string      `json:"required_resource"`
	UserResources    interface{} `json:"user_resources"`
}

// PermissionValidationResponse represents permission validation response
type PermissionValidationResponse struct {
	Message          string      `json:"message"`
	RequiredScope    string      `json:"required_scope"`
	RequiredResource string      `json:"required_resource"`
	UserScopes       interface{} `json:"user_scopes"`
	UserResources    interface{} `json:"user_resources"`
}

// ErrorResponse represents error responses
type ErrorResponse struct {
	Error            string   `json:"error"`
	Details          string   `json:"details,omitempty"`
	RequiredScope    string   `json:"required_scope,omitempty"`
	RequiredResource string   `json:"required_resource,omitempty"`
	CurrentMethod    string   `json:"current_method,omitempty"`
	AllowedMethods   []string `json:"allowed_methods,omitempty"`
}
