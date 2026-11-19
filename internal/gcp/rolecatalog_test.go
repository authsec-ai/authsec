package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// fakeIAMRoles serves roles.get and the custom role listings.
type fakeIAMRoles struct {
	srv     *httptest.Server
	gets    int32
	lists   int32
	custom  map[string][]map[string]any // parent -> roles
	roles   map[string]map[string]any   // name -> role (predefined / custom get)
	getFail map[string]int              // name -> HTTP status
	pages   bool                        // serve an endless next-page token
}

func newFakeIAMRoles(t *testing.T) *fakeIAMRoles {
	t.Helper()
	f := &fakeIAMRoles{
		custom:  map[string][]map[string]any{},
		roles:   map[string]map[string]any{},
		getFail: map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIAMRoles) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	w.Header().Set("Content-Type", "application/json")
	if strings.HasSuffix(path, "/roles") { // organizations/X/roles, projects/X/roles
		atomic.AddInt32(&f.lists, 1)
		parent := strings.TrimSuffix(path, "/roles")
		resp := map[string]any{"roles": f.custom[parent]}
		if f.pages {
			resp["nextPageToken"] = "more"
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	atomic.AddInt32(&f.gets, 1)
	if code, ok := f.getFail[path]; ok {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"error":{"code":` + strconv.Itoa(code) + `,"message":"refused"}}`))
		return
	}
	role, ok := f.roles[path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":404,"message":"not found"}}`))
		return
	}
	_ = json.NewEncoder(w).Encode(role)
}

func (f *fakeIAMRoles) service(t *testing.T) *iam.Service {
	t.Helper()
	svc, err := iam.NewService(context.Background(),
		option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("iam service: %v", err)
	}
	return svc
}

func TestRoleCatalog_BasicRolesAreNeverExpandedOrFetched(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	c, err := LoadCatalog(context.Background(), f.service(t), NewGovernor(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"roles/owner", "roles/editor", "roles/viewer"} {
		r, err := c.Expand(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		if !r.Basic || len(r.Permissions) != 0 || r.Unresolved {
			t.Fatalf("%s = %+v, want Basic with no permissions", name, r)
		}
	}
	if f.gets != 0 {
		t.Fatalf("basic roles caused %d roles.get calls, want 0", f.gets)
	}
}

func TestRoleCatalog_PredefinedRoleIsFetchedOnceAndCachedAcrossScans(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	f.roles["roles/storage.objectViewer"] = map[string]any{
		"name": "roles/storage.objectViewer", "etag": "e1", "stage": "GA",
		"includedPermissions": []string{"storage.objects.get", "storage.objects.list"},
	}
	for scan := 0; scan < 2; scan++ {
		c, _ := LoadCatalog(context.Background(), f.service(t), NewGovernor(), nil)
		for i := 0; i < 3; i++ { // same role, many members
			r, err := c.Expand(context.Background(), "roles/storage.objectViewer")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Permissions) != 2 || r.Etag != "e1" || r.Stage != RoleStageGA {
				t.Fatalf("role = %+v", r)
			}
		}
	}
	if f.gets != 1 {
		t.Fatalf("roles.get called %d times across two scans, want 1 (cache)", f.gets)
	}
}

func TestRoleCatalog_CacheExpires(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	f.roles["roles/pubsub.viewer"] = map[string]any{"name": "roles/pubsub.viewer", "includedPermissions": []string{"pubsub.topics.get"}}
	c, _ := LoadCatalog(context.Background(), f.service(t), NewGovernor(), nil)
	now := time.Now()
	c.now = func() time.Time { return now }
	if _, err := c.Expand(context.Background(), "roles/pubsub.viewer"); err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return now.Add(roleCacheTTL + time.Minute) }
	if _, err := c.Expand(context.Background(), "roles/pubsub.viewer"); err != nil {
		t.Fatal(err)
	}
	if f.gets != 2 {
		t.Fatalf("gets = %d, want 2 after the TTL", f.gets)
	}
}

func TestRoleCatalog_CustomRolesListedAndResolvedWithoutGet(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	f.custom["projects/dev"] = []map[string]any{{
		"name": "projects/dev/roles/igaDeployer", "stage": "GA",
		"includedPermissions": []string{"iam.serviceAccounts.actAs", "run.services.update"},
	}}
	c, err := LoadCatalog(context.Background(), f.service(t), NewGovernor(), []string{"projects/dev"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Expand(context.Background(), "projects/dev/roles/igaDeployer")
	if err != nil || !r.Custom || len(r.Permissions) != 2 || r.Unresolved {
		t.Fatalf("role = %+v err=%v", r, err)
	}
	if f.gets != 0 {
		t.Fatalf("a listed custom role cost %d roles.get calls, want 0", f.gets)
	}
}

func TestRoleCatalog_DeletedCustomRoleIsUnresolved(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	f.custom["projects/dev"] = []map[string]any{{
		"name": "projects/dev/roles/gone", "deleted": true, "stage": "DISABLED",
	}}
	c, _ := LoadCatalog(context.Background(), f.service(t), NewGovernor(), []string{"projects/dev"})
	r, err := c.Expand(context.Background(), "projects/dev/roles/gone")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Unresolved || !r.Deleted || r.Stage != RoleStageDisabled {
		t.Fatalf("role = %+v, want unresolved+deleted+DISABLED", r)
	}
}

func TestRoleCatalog_NotFoundIsUnresolvedNotAnError(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	c, _ := LoadCatalog(context.Background(), f.service(t), NewGovernor(), nil)
	r, err := c.Expand(context.Background(), "projects/dev/roles/neverExisted")
	if err != nil {
		t.Fatalf("a 404 must not be an error: %v", err)
	}
	if !r.Unresolved || !r.Custom {
		t.Fatalf("role = %+v, want unresolved custom", r)
	}
}

func TestRoleCatalog_OtherFailureIsAnError(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	f.getFail["roles/secretmanager.admin"] = http.StatusForbidden
	c, _ := LoadCatalog(context.Background(), f.service(t), NewGovernor(), nil)
	r, err := c.Expand(context.Background(), "roles/secretmanager.admin")
	if err == nil {
		t.Fatalf("a refused roles.get must be an error, got %+v", r)
	}
	if r.Unresolved {
		t.Fatal("could-not-ask must not read as the role being gone")
	}
}

func TestRoleCatalog_UnresolvedPredefinedRoleIsNotCached(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	c, _ := LoadCatalog(context.Background(), f.service(t), NewGovernor(), nil)
	if _, err := c.Expand(context.Background(), "roles/not.a.role"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Expand(context.Background(), "roles/not.a.role"); err != nil {
		t.Fatal(err)
	}
	if f.gets != 2 {
		t.Fatalf("gets = %d: a 404 must not be cached as an answer", f.gets)
	}
}

func TestRoleCatalog_ListPageCeilingIsAnError(t *testing.T) {
	ResetPredefinedRoleCache()
	f := newFakeIAMRoles(t)
	f.pages = true
	_, err := LoadCatalog(context.Background(), f.service(t), NewGovernor(), []string{"projects/dev"})
	if err == nil || !strings.Contains(err.Error(), ErrRolePagesExceeded.Error()) {
		t.Fatalf("err = %v, want the page ceiling", err)
	}
}

func TestIsBasicAndCustomRole(t *testing.T) {
	for name, want := range map[string]bool{"roles/owner": true, "roles/editor": true, "roles/viewer": true, "roles/storage.admin": false} {
		if IsBasicRole(name) != want {
			t.Errorf("IsBasicRole(%q) != %v", name, want)
		}
	}
	for name, want := range map[string]bool{"projects/p/roles/x": true, "organizations/1/roles/y": true, "roles/viewer": false} {
		if IsCustomRole(name) != want {
			t.Errorf("IsCustomRole(%q) != %v", name, want)
		}
	}
}
