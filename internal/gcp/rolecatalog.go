package gcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/api/iam/v1"
)

/* rolecatalog.go answers "what does this role grant", so a binding row can carry
   the expanded permission list.

   WHAT IT READS. Custom roles are listed (organization and project parents: a
   handful, cheap). Predefined roles are fetched one at a time with roles.get, and
   only for the roles a binding actually names -- listing the whole predefined
   catalog is ~2000 roles and thousands of permissions each, to answer a question
   a project asks about a dozen roles.

   BASIC ROLES ARE NEVER EXPANDED. roles/owner, roles/editor and roles/viewer run
   to thousands of permissions; copied onto every row for every member they would
   dwarf the rest of the table. They come back flagged Basic with no permission
   list; the read side expands them from Google's own role data when it needs to.

   NOT FOUND IS AN ANSWER, NOT AN ERROR. A custom role that was deleted while its
   bindings stayed behind is real and common. Expand reports it as unresolved so
   the binding is kept and flagged. Any other failure is an error: the caller must
   not turn "could not ask" into "the role is gone".

   CACHE. A predefined role is cached across scans, keyed by name and stamped with
   the etag Google returned. roles.get cannot be made conditional on an etag, so
   the cache is a time-to-live, and the etag is kept so a refresh that returns the
   same etag is recognisable as unchanged. Custom roles are never cached across
   scans: a customer edits them. */

// Role launch stages as Google reports them.
const (
	RoleStageGA         = "GA"
	RoleStageBeta       = "BETA"
	RoleStageAlpha      = "ALPHA"
	RoleStageDeprecated = "DEPRECATED"
	RoleStageDisabled   = "DISABLED"
	RoleStageEAP        = "EAP"
)

// roleMaxPages bounds the custom-role listing per parent.
const roleMaxPages = 50

// roleCacheTTL is how long a predefined role's permission list is trusted
// without asking Google again.
const roleCacheTTL = 12 * time.Hour

// ErrRolePagesExceeded means a custom-role listing hit its page ceiling, so the
// catalog is not known to be whole.
var ErrRolePagesExceeded = fmt.Errorf("gcp: custom role listing exceeded %d pages", roleMaxPages)

// basicRoles are the three legacy roles; see the file comment.
var basicRoles = map[string]struct{}{
	"roles/owner":  {},
	"roles/editor": {},
	"roles/viewer": {},
}

// IsBasicRole reports whether name is roles/owner, roles/editor or roles/viewer.
func IsBasicRole(name string) bool {
	_, ok := basicRoles[name]
	return ok
}

// IsCustomRole reports whether name is an organization or project custom role.
func IsCustomRole(name string) bool {
	return strings.HasPrefix(name, "organizations/") || strings.HasPrefix(name, "projects/")
}

// Role is one role as the catalog knows it.
type Role struct {
	Name        string
	Title       string
	Stage       string
	Etag        string
	Permissions []string
	// Basic roles carry no Permissions by design.
	Basic bool
	// Custom is an organization or project role.
	Custom bool
	// Deleted is Google's own flag on a deleted custom role.
	Deleted bool
	// Unresolved: the role does not exist (any more), or is deleted. The binding
	// naming it is kept and flagged; it has no permissions to expand.
	Unresolved bool
}

type cachedRole struct {
	role    Role
	fetched time.Time
}

var (
	predefinedMu    sync.Mutex
	predefinedCache = map[string]cachedRole{}
)

// ResetPredefinedRoleCache empties the cross-scan cache. For tests.
func ResetPredefinedRoleCache() {
	predefinedMu.Lock()
	defer predefinedMu.Unlock()
	predefinedCache = map[string]cachedRole{}
}

// RoleCatalog resolves role names for one scan.
type RoleCatalog struct {
	svc      *iam.Service
	governor *Governor
	now      func() time.Time

	mu     sync.Mutex
	custom map[string]Role
	// Fetches counts roles.get calls, for tests and the scan report.
	fetches int
}

// LoadCatalog lists the custom roles under each parent ("organizations/<id>" or
// "projects/<id>") and returns a catalog ready to Expand.
//
// An error means the custom-role listing was not completed for at least one
// parent; the catalog returned alongside it still holds what was read, so a
// caller can keep going and report the surface not reached.
func LoadCatalog(ctx context.Context, svc *iam.Service, governor *Governor, parents []string) (*RoleCatalog, error) {
	c := &RoleCatalog{svc: svc, governor: governor, now: time.Now, custom: map[string]Role{}}
	var firstErr error
	for _, parent := range parents {
		if err := c.listCustom(ctx, parent); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("list custom roles under %s: %w", parent, err)
		}
	}
	return c, firstErr
}

func (c *RoleCatalog) listCustom(ctx context.Context, parent string) error {
	token := ""
	for page := 0; page < roleMaxPages; page++ {
		var resp *iam.ListRolesResponse
		pageToken := token
		if err := Retry(ctx, func() error {
			if err := c.governor.IAM.Wait(ctx); err != nil {
				return err
			}
			var out *iam.ListRolesResponse
			var callErr error
			if strings.HasPrefix(parent, "organizations/") {
				out, callErr = c.svc.Organizations.Roles.List(parent).
					View("FULL").ShowDeleted(true).PageToken(pageToken).Context(ctx).Do()
			} else {
				out, callErr = c.svc.Projects.Roles.List(parent).
					View("FULL").ShowDeleted(true).PageToken(pageToken).Context(ctx).Do()
			}
			if callErr != nil {
				return callErr
			}
			resp = out
			return nil
		}); err != nil {
			return err
		}
		c.mu.Lock()
		for _, r := range resp.Roles {
			c.custom[r.Name] = roleFrom(r, true)
		}
		c.mu.Unlock()
		if resp.NextPageToken == "" {
			return nil
		}
		token = resp.NextPageToken
	}
	return ErrRolePagesExceeded
}

// Fetches reports how many roles.get calls this catalog has made.
func (c *RoleCatalog) Fetches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetches
}

// Expand returns the role named, resolving it from the catalog, the cross-scan
// cache or roles.get. A role that does not exist comes back Unresolved with a nil
// error. A role that could not be asked about comes back as an error.
func (c *RoleCatalog) Expand(ctx context.Context, name string) (Role, error) {
	if IsBasicRole(name) {
		return Role{Name: name, Stage: RoleStageGA, Basic: true}, nil
	}

	c.mu.Lock()
	if r, ok := c.custom[name]; ok {
		c.mu.Unlock()
		if r.Deleted {
			r.Unresolved = true
		}
		return r, nil
	}
	c.mu.Unlock()

	custom := IsCustomRole(name)
	if !custom {
		predefinedMu.Lock()
		cached, ok := predefinedCache[name]
		predefinedMu.Unlock()
		if ok && c.now().Sub(cached.fetched) < roleCacheTTL {
			return cached.role, nil
		}
	}

	role, err := c.get(ctx, name, custom)
	if err != nil {
		return Role{Name: name, Custom: custom}, err
	}
	if custom {
		c.mu.Lock()
		c.custom[name] = role
		c.mu.Unlock()
	} else if !role.Unresolved {
		predefinedMu.Lock()
		predefinedCache[name] = cachedRole{role: role, fetched: c.now()}
		predefinedMu.Unlock()
	}
	if role.Deleted {
		role.Unresolved = true
	}
	return role, nil
}

func (c *RoleCatalog) get(ctx context.Context, name string, custom bool) (Role, error) {
	var out *iam.Role
	err := Retry(ctx, func() error {
		if err := c.governor.IAM.Wait(ctx); err != nil {
			return err
		}
		c.mu.Lock()
		c.fetches++
		c.mu.Unlock()
		r, callErr := c.svc.Roles.Get(name).Context(ctx).Do()
		if callErr != nil {
			return callErr
		}
		out = r
		return nil
	})
	switch {
	case err == nil:
		return roleFrom(out, custom), nil
	case isNotFound(err):
		return Role{Name: name, Custom: custom, Unresolved: true}, nil
	default:
		return Role{}, err
	}
}

func roleFrom(r *iam.Role, custom bool) Role {
	stage := r.Stage
	if stage == "" {
		stage = RoleStageGA
	}
	perms := append([]string(nil), r.IncludedPermissions...)
	return Role{
		Name:        r.Name,
		Title:       r.Title,
		Stage:       stage,
		Etag:        r.Etag,
		Permissions: perms,
		Custom:      custom,
		Deleted:     r.Deleted,
	}
}
