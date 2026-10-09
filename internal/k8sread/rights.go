package k8sread

import "encoding/json"

// expandRights lifts the rule's lists out of native_rights.
//
// Stored as jsonb and read back rather than kept as columns because a
// Kubernetes rule is a cross product of four lists, and flattening it into
// columns would either lose the distinction between "all verbs on secrets" and
// "get on everything" or need four array columns nothing else uses.
//
// A rule that fails to decode yields empty lists and keeps its flags, which is
// the honest degradation: the console shows a rule it cannot detail rather than
// dropping a grant from the list.
func expandRights(g *Grant, native []byte) {
	if len(native) == 0 {
		return
	}
	var r struct {
		APIGroups       []string `json:"api_groups"`
		Resources       []string `json:"resources"`
		ResourceNames   []string `json:"resource_names"`
		NonResourceURLs []string `json:"non_resource_urls"`
		Verbs           []string `json:"verbs"`
	}
	if err := json.Unmarshal(native, &r); err != nil {
		return
	}
	g.APIGroups, g.Resources = r.APIGroups, r.Resources
	g.ResourceNames, g.NonResourceURLs = r.ResourceNames, r.NonResourceURLs
	g.Verbs = r.Verbs
}
