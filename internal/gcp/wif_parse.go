package gcp

import "regexp"

// providerResourcePattern matches a bare WIF provider resource name (no
// "//iam.googleapis.com/" scheme prefix — see credentials.go's audiencePrefix
// doc comment for why the bare form is what's stored and pasted), capturing
// the pool id and provider id segments:
//
//	projects/<NUM>/locations/global/workloadIdentityPools/<pool_id>/providers/<provider_id>
var providerResourcePattern = regexp.MustCompile(
	`^projects/\d+/locations/global/workloadIdentityPools/([^/]+)/providers/([^/]+)$`)

// ParseProviderResource extracts the pool id and provider id segments from a
// bare WIF provider resource name. ok is false when providerResource does not
// match the expected shape at all (not this function's job to say why —
// the caller's cross-check against DeriveWIFParams's own output is what
// actually validates it; this only splits the string apart).
func ParseProviderResource(providerResource string) (poolID, providerID string, ok bool) {
	m := providerResourcePattern.FindStringSubmatch(providerResource)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}
