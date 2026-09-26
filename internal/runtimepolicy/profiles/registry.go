// Package profiles is the certified-profile registry. A profile plus a
// capability digest names the controls that digest has been shown to enforce.
// A version string alone is not enough.
package profiles

import (
	"embed"
	"encoding/json"
	"sort"
	"sync"
)

const (
	LinuxManagedV1 = "linux-managed-v1"
	K8sAdmissionV1 = "k8s-admission-v1"
)

//go:embed *.json
var files embed.FS

// FilesystemBaseline is what a managed filesystem profile supplies besides
// the path rule an administrator typed.
type FilesystemBaseline struct {
	Loaders        map[string]string `json:"loaders"`
	Libraries      []string          `json:"libraries"`
	Certificates   []string          `json:"certificates"`
	ReadonlyConfig []string          `json:"readonly_config"`
}

type fileProfile struct {
	Profile            string              `json:"profile"`
	FilesystemBaseline FilesystemBaseline  `json:"filesystem_baseline"`
	CertifiedDigests   map[string][]string `json:"certified_digests"`
	// TestOnlyDigests are fixtures. Supports ignores them. Tests opt in with
	// WithTestDigests. A7 must not treat these digests as certified.
	TestOnlyDigests map[string][]string `json:"test_only_digests"`
}

// Registry maps profile and capability digest to enforceable controls.
type Registry struct {
	byName map[string]fileProfile
}

var (
	once sync.Once
	reg  *Registry
	errL error
)

// Load returns the embedded registry. It is safe for concurrent use.
func Load() (*Registry, error) {
	once.Do(func() {
		reg = &Registry{byName: map[string]fileProfile{}}
		names, err := files.ReadDir(".")
		if err != nil {
			errL = err
			return
		}
		for _, name := range names {
			body, err := files.ReadFile(name.Name())
			if err != nil {
				errL = err
				return
			}
			var p fileProfile
			if err := json.Unmarshal(body, &p); err != nil {
				errL = err
				return
			}
			reg.byName[p.Profile] = p
		}
	})
	return reg, errL
}

// Known reports whether the profile is in the registry.
func (r *Registry) Known(profile string) bool {
	_, ok := r.byName[profile]
	return ok
}

// Baseline is the filesystem profile for profile, if one is defined.
func (r *Registry) Baseline(profile string) (FilesystemBaseline, bool) {
	p, ok := r.byName[profile]
	if !ok {
		return FilesystemBaseline{}, false
	}
	return p.FilesystemBaseline, true
}

// Supports reports whether digest is certified to enforce control on profile.
// An unknown digest supports nothing.
func (r *Registry) Supports(profile, digest, control string) bool {
	p, ok := r.byName[profile]
	if !ok {
		return false
	}
	for _, c := range p.CertifiedDigests[digest] {
		if c == control {
			return true
		}
	}
	return false
}

// WithTestDigests returns a copy whose fixture digests count as certified.
// Load itself does not. Callers that ship a decision use Load.
func (r *Registry) WithTestDigests() *Registry {
	if r == nil {
		return nil
	}
	out := &Registry{byName: map[string]fileProfile{}}
	for name, p := range r.byName {
		cp := p
		cp.CertifiedDigests = map[string][]string{}
		for k, v := range p.CertifiedDigests {
			cp.CertifiedDigests[k] = append([]string(nil), v...)
		}
		for k, v := range p.TestOnlyDigests {
			cp.CertifiedDigests[k] = append([]string(nil), v...)
		}
		cp.TestOnlyDigests = nil
		out.byName[name] = cp
	}
	return out
}

// Controls returns the certified controls for a digest, sorted. An unknown
// digest returns nil.
func (r *Registry) Controls(profile, digest string) []string {
	p, ok := r.byName[profile]
	if !ok {
		return nil
	}
	out := append([]string(nil), p.CertifiedDigests[digest]...)
	sort.Strings(out)
	return out
}
