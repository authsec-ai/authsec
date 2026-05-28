package middlewares

// Phase 6: GetTenantIDSafely was removed — callers should use the workspace_id
// context key (populated by AuthMiddleware) directly via c.GetString("workspace_id").
