package sharedmodels

// Introspection represents token introspection response
// This duplicates the shared model temporarily until proper integration
type Introspection struct {
	Active   *bool                  `json:"active"`
	Scope    string                 `json:"scope"`
	ClientID string                 `json:"client_id"`
	Ext      map[string]interface{} `json:"ext"`
}
