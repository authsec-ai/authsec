package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/models"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/option"
)

// fakeHierarchy serves Resource Manager folders.list and projects:search from an
// in-memory parent -> children map, so the walk is exercised through the real
// generated client rather than a mocked interface.
type fakeHierarchy struct {
	srv *httptest.Server

	// folders and projects are keyed by parent resource name.
	folders  map[string][]*cloudresourcemanager.Folder
	projects map[string][]*cloudresourcemanager.Project
	// failFolders makes folders.list fail with that status.
	failFolders int
	// pageSize, when >0, pages every list that many items at a time.
	pageSize int

	mu    sync.Mutex
	calls []string
}

func newFakeHierarchy() *fakeHierarchy {
	f := &fakeHierarchy{
		folders:  map[string][]*cloudresourcemanager.Folder{},
		projects: map[string][]*cloudresourcemanager.Project{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeHierarchy) addFolder(parent, id, name string) {
	f.folders[parent] = append(f.folders[parent], &cloudresourcemanager.Folder{
		Name: "folders/" + id, DisplayName: name, State: "ACTIVE", Parent: parent,
	})
}

func (f *fakeHierarchy) addProject(parent, id, number string) {
	f.projects[parent] = append(f.projects[parent], &cloudresourcemanager.Project{
		Name: "projects/" + number, ProjectId: id, State: "ACTIVE", Parent: parent,
	})
}

func (f *fakeHierarchy) callCount(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func pageOf[T any](all []T, size int, token string) ([]T, string) {
	start := 0
	if token != "" {
		fmt.Sscanf(token, "p%d", &start)
	}
	end := len(all)
	if size > 0 && start+size < end {
		end = start + size
	}
	next := ""
	if end < len(all) {
		next = fmt.Sprintf("p%d", end)
	}
	if start > len(all) {
		start = len(all)
	}
	return all[start:end], next
}

func (f *fakeHierarchy) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.calls = append(f.calls, r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	q := r.URL.Query()

	switch {
	case strings.HasSuffix(r.URL.Path, "/folders"):
		if f.failFolders != 0 {
			w.WriteHeader(f.failFolders)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": f.failFolders, "message": "denied"}})
			return
		}
		items, next := pageOf(f.folders[q.Get("parent")], f.pageSize, q.Get("pageToken"))
		_ = json.NewEncoder(w).Encode(cloudresourcemanager.ListFoldersResponse{Folders: items, NextPageToken: next})

	case strings.HasSuffix(r.URL.Path, "/projects:search"):
		parent := strings.TrimPrefix(q.Get("query"), "parent:")
		items, next := pageOf(f.projects[parent], f.pageSize, q.Get("pageToken"))
		_ = json.NewEncoder(w).Encode(cloudresourcemanager.SearchProjectsResponse{Projects: items, NextPageToken: next})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeHierarchy) walker(t *testing.T) *ScopeTreeWalker {
	t.Helper()
	t.Cleanup(f.srv.Close)
	// The governor paces a real scan; the walk's own behaviour is under test, not
	// the pacing, and the 300-folder case would otherwise take minutes.
	t.Setenv(EnvIAMQPS, "100000")
	rm, err := cloudresourcemanager.NewService(context.Background(),
		option.WithEndpoint(f.srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("rm client: %v", err)
	}
	return &ScopeTreeWalker{RM: rm, Governor: NewGovernor()}
}

func ids(nodes []ScopeNode, kind string) []string {
	var out []string
	for _, n := range nodes {
		if n.Kind == kind {
			out = append(out, n.ID)
		}
	}
	return out
}

// The reason the walk exists: a project nested in a folder is not returned by
// "parent:organizations/N", so the old single search missed it.
func TestScopeTree_FindsProjectsNestedInFolders(t *testing.T) {
	f := newFakeHierarchy()
	f.addProject("organizations/1", "top-project", "100")
	f.addFolder("organizations/1", "10", "Engineering")
	f.addFolder("folders/10", "11", "Platform")
	f.addProject("folders/10", "eng-project", "101")
	f.addProject("folders/11", "deep-project", "102")

	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeOrg, "1")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if tree.Truncated {
		t.Fatalf("unexpectedly truncated: %s", tree.TruncatedReason)
	}
	got := ids(tree.Nodes, ScopeNodeProject)
	want := map[string]bool{"top-project": true, "eng-project": true, "deep-project": true}
	if len(got) != len(want) {
		t.Fatalf("projects = %v, want %v", got, want)
	}
	for _, id := range got {
		if !want[id] {
			t.Fatalf("unexpected project %q in %v", id, got)
		}
	}
	// Parent links make it a tree and not a flat list.
	for _, n := range tree.Nodes {
		if n.ID == "deep-project" && n.Parent != "folders/11" {
			t.Fatalf("deep-project parent = %q, want folders/11", n.Parent)
		}
		if n.ID == "11" && (n.Parent != "folders/10" || n.DisplayName != "Platform") {
			t.Fatalf("folder 11 = %+v", n)
		}
		if n.ID == "deep-project" && n.Number != "102" {
			t.Fatalf("project number = %q, want 102", n.Number)
		}
	}
	if tree.Nodes[0].Kind != ScopeNodeOrganization || tree.Nodes[0].ID != "1" {
		t.Fatalf("root = %+v", tree.Nodes[0])
	}
}

func TestScopeTree_FolderScopeStartsAtTheFolder(t *testing.T) {
	f := newFakeHierarchy()
	f.addFolder("folders/10", "11", "Platform")
	f.addProject("folders/11", "p", "1")
	// Outside the connector's folder; must never appear.
	f.addProject("organizations/1", "outside", "9")

	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeFolder, "10")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if got := ids(tree.Nodes, ScopeNodeProject); len(got) != 1 || got[0] != "p" {
		t.Fatalf("projects = %v, want [p]", got)
	}
	if tree.Nodes[0].Kind != ScopeNodeFolder {
		t.Fatalf("root kind = %q", tree.Nodes[0].Kind)
	}
}

func TestScopeTree_ProjectScopeCostsNoCalls(t *testing.T) {
	f := newFakeHierarchy()
	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeProject, "my-proj")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(tree.Nodes) != 1 || tree.Nodes[0].ID != "my-proj" || tree.Nodes[0].Kind != ScopeNodeProject {
		t.Fatalf("tree = %+v", tree.Nodes)
	}
	if n := f.callCount("/"); n != 0 {
		t.Fatalf("a project scope made %d calls, want 0", n)
	}
}

func TestScopeTree_PaginatesFoldersAndProjects(t *testing.T) {
	f := newFakeHierarchy()
	f.pageSize = 1
	for i := 0; i < 3; i++ {
		f.addFolder("organizations/1", fmt.Sprintf("f%d", i), "f")
		f.addProject("organizations/1", fmt.Sprintf("p%d", i), fmt.Sprintf("%d", i))
	}
	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeOrg, "1")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if n := len(ids(tree.Nodes, ScopeNodeFolder)); n != 3 {
		t.Fatalf("folders = %d, want 3", n)
	}
	if n := len(ids(tree.Nodes, ScopeNodeProject)); n != 3 {
		t.Fatalf("projects = %d, want 3", n)
	}
}

func TestScopeTree_SkipsFoldersAndProjectsBeingDeleted(t *testing.T) {
	f := newFakeHierarchy()
	f.folders["organizations/1"] = []*cloudresourcemanager.Folder{
		{Name: "folders/1", State: "DELETE_REQUESTED"},
	}
	f.projects["organizations/1"] = []*cloudresourcemanager.Project{
		{Name: "projects/1", ProjectId: "gone", State: "DELETE_REQUESTED"},
		{Name: "projects/2", ProjectId: "live", State: "ACTIVE"},
	}
	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeOrg, "1")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if got := ids(tree.Nodes, ScopeNodeProject); len(got) != 1 || got[0] != "live" {
		t.Fatalf("projects = %v, want [live]", got)
	}
	if len(ids(tree.Nodes, ScopeNodeFolder)) != 0 {
		t.Fatal("a folder being deleted was walked")
	}
}

// Folders nested deeper than the documented limit are reported, never silently
// dropped: a truncated walk must not be mistaken for the whole estate.
func TestScopeTree_StopsAtMaxDepthAndSaysSo(t *testing.T) {
	f := newFakeHierarchy()
	parent := "organizations/1"
	for d := 1; d <= MaxFolderDepth+2; d++ {
		id := fmt.Sprintf("%d", d)
		f.addFolder(parent, id, "level")
		parent = "folders/" + id
	}
	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeOrg, "1")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !tree.Truncated || tree.TruncatedReason == "" {
		t.Fatal("a tree deeper than MaxFolderDepth must be marked truncated with a reason")
	}
	if got := len(ids(tree.Nodes, ScopeNodeFolder)); got != MaxFolderDepth {
		t.Fatalf("folders walked = %d, want exactly %d", got, MaxFolderDepth)
	}
}

func TestScopeTree_ExactlyMaxDepthIsNotTruncated(t *testing.T) {
	f := newFakeHierarchy()
	parent := "organizations/1"
	for d := 1; d <= MaxFolderDepth; d++ {
		id := fmt.Sprintf("%d", d)
		f.addFolder(parent, id, "level")
		parent = "folders/" + id
	}
	f.addProject(parent, "bottom", "1")
	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeOrg, "1")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if tree.Truncated {
		t.Fatalf("a tree exactly at the limit is whole, got truncated: %s", tree.TruncatedReason)
	}
	if got := ids(tree.Nodes, ScopeNodeProject); len(got) != 1 {
		t.Fatalf("projects = %v, want [bottom]", got)
	}
}

func TestScopeTree_TooManyFoldersUnderOneParentIsTruncated(t *testing.T) {
	f := newFakeHierarchy()
	f.pageSize = 100
	for i := 0; i < MaxFoldersPerParent+5; i++ {
		f.addFolder("organizations/1", fmt.Sprintf("f%d", i), "x")
	}
	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeOrg, "1")
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !tree.Truncated {
		t.Fatal("more than MaxFoldersPerParent folders must be marked truncated")
	}
	if got := len(ids(tree.Nodes, ScopeNodeFolder)); got != MaxFoldersPerParent {
		t.Fatalf("folders kept = %d, want the cap %d", got, MaxFoldersPerParent)
	}
}

// A denied folders.list is a failure to look, and returns no tree at all -- a
// half-walked tree must not be stored as if it were whole.
func TestScopeTree_DeniedFolderListReturnsNoTree(t *testing.T) {
	f := newFakeHierarchy()
	f.failFolders = http.StatusForbidden
	tree, err := f.walker(t).Walk(context.Background(), models.CloudScopeOrg, "1")
	if err == nil {
		t.Fatalf("want an error, got tree %+v", tree)
	}
	if tree != nil {
		t.Fatal("an error must not come with a partial tree")
	}
}

func TestScopeTree_RejectsUnknownScopeKind(t *testing.T) {
	f := newFakeHierarchy()
	if _, err := f.walker(t).Walk(context.Background(), "galaxy", "1"); err == nil {
		t.Fatal("an unknown scope kind must be refused")
	}
}

func TestGovernor_IAMDefaultIsFour(t *testing.T) {
	if defaultIAMQPS != 4.0 {
		t.Fatalf("defaultIAMQPS = %v, want 4 (GCP-1)", defaultIAMQPS)
	}
}

func TestReaderRoleSetVersions(t *testing.T) {
	if ReaderRoleSetVersion != "gcp-reader-p1-v3" {
		t.Fatalf("current role set = %q: bump it only together with the roles", ReaderRoleSetVersion)
	}
	if ReaderRoleSetVersionP2 != "gcp-reader-p2" {
		t.Fatalf("p2 label = %q", ReaderRoleSetVersionP2)
	}
}
