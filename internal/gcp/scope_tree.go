package gcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
)

/* scope_tree.go walks the resource hierarchy under a connector's scope:
   organization -> folders (recursive) -> projects.

   WHY A WALK AND NOT ONE PROJECT SEARCH. projects.search with
   "parent:organizations/N" returns the projects whose DIRECT parent is that
   organization. A project nested in a folder is not returned, so a scan built on
   that query silently read only the top level of an org. Walking folders and
   asking each parent for its own projects is what actually finds the estate.

   THE TREE IS THE PROJECT SET. The scan derives the projects it reads from this
   tree, so the stored tree and what was scanned can never disagree.

   BOUNDED, AND SAYS SO. Depth and per-parent fan-out are capped at the
   documented hierarchy limits (scope.go). Hitting either is reported on the tree
   (Truncated) and the scan records the scope_tree surface as not reached, so a
   truncated walk can never reconcile -- it is not evidence that anything is
   gone. */

// SurfaceScopeTree is the scan's structural surface for the hierarchy walk. It
// is not a probe surface (it is not in AllSurfaces): the probe asks whether the
// walk is possible, this records whether a scan completed one.
const (
	SurfaceScopeTree        = "scope_tree"
	SurfaceHMACKeys         = "hmac_keys"
	SurfaceAPIKeys          = "api_keys"
	SurfaceFederationConfig = "federation_config"
)

// Node kinds in a ScopeTree.
const (
	ScopeNodeOrganization = "organization"
	ScopeNodeFolder       = "folder"
	ScopeNodeProject      = "project"
)

// scopeTreeMaxPages bounds pagination per parent, per call type, for the same
// reason the identity collectors cap theirs.
const scopeTreeMaxPages = 200

// ErrScopeTreeTruncated means the walk stopped at a hierarchy limit. The nodes
// found are real; the tree is not the whole estate.
var ErrScopeTreeTruncated = errors.New("gcp: scope tree walk stopped at a hierarchy limit")

// ScopeNode is one organization, folder or project.
type ScopeNode struct {
	// ID is the organization or folder number, or the project id.
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Parent is the parent's resource name ("organizations/1", "folders/2"), empty
	// for the connector's own scope.
	Parent      string `json:"parent,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state,omitempty"`
	// Number is a project's immutable number. A project id can be reused after
	// deletion; the number cannot.
	Number string `json:"number,omitempty"`
}

// ScopeTree is the walked hierarchy, stored on the connector at attrs.scope_tree.
type ScopeTree struct {
	Nodes           []ScopeNode `json:"nodes"`
	Truncated       bool        `json:"truncated,omitempty"`
	TruncatedReason string      `json:"truncated_reason,omitempty"`
	WalkedAt        time.Time   `json:"walked_at"`
}

// Projects returns the project nodes.
func (t *ScopeTree) Projects() []ScopeNode {
	var out []ScopeNode
	for _, n := range t.Nodes {
		if n.Kind == ScopeNodeProject {
			out = append(out, n)
		}
	}
	return out
}

// ScopeTreeWalker lists the hierarchy. A struct so the Resource Manager client
// and the budget are supplied once.
type ScopeTreeWalker struct {
	RM       *cloudresourcemanager.Service
	Governor *Governor
	Now      func() time.Time
}

// scopeNodeKind maps a connector scope kind to the node kind in a ScopeTree. The
// resource name itself comes from scopeResourceName (scope.go), which already
// owns that dispatch.
func scopeNodeKind(scopeKind string) (string, error) {
	switch scopeKind {
	case models.CloudScopeOrg:
		return ScopeNodeOrganization, nil
	case models.CloudScopeFolder:
		return ScopeNodeFolder, nil
	case models.CloudScopeProject:
		return ScopeNodeProject, nil
	}
	return "", fmt.Errorf("%w: cannot walk scope kind %q", ErrInvalidGrant, scopeKind)
}

// Walk builds the tree under scopeKind/scopeID.
//
// A project scope is a single node and costs no calls. Any call error returns
// no tree at all: a half-walked tree is not stored as if it were whole.
// A hierarchy limit returns the tree found so far with Truncated set and a nil
// error; the caller decides what that means for coverage.
func (w *ScopeTreeWalker) Walk(ctx context.Context, scopeKind, scopeID string) (*ScopeTree, error) {
	rootKind, err := scopeNodeKind(scopeKind)
	if err != nil {
		return nil, err
	}
	rootName, err := scopeResourceName(scopeKind, scopeID)
	if err != nil {
		return nil, err
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	tree := &ScopeTree{WalkedAt: now().UTC()}
	tree.Nodes = append(tree.Nodes, ScopeNode{ID: scopeID, Kind: rootKind})
	if scopeKind == models.CloudScopeProject {
		return tree, nil
	}

	type parentRef struct {
		name  string
		depth int
	}
	queue := []parentRef{{name: rootName, depth: 0}}
	seen := map[string]bool{rootName: true}

	truncate := func(reason string) {
		if !tree.Truncated {
			tree.Truncated = true
			tree.TruncatedReason = reason
		}
	}

	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]

		folders, err := w.listFolders(ctx, p.name)
		if err != nil {
			return nil, err
		}
		if len(folders) > MaxFoldersPerParent {
			truncate(fmt.Sprintf("%s has more than %d folders", p.name, MaxFoldersPerParent))
			folders = folders[:MaxFoldersPerParent]
		}
		for _, f := range folders {
			if p.depth+1 > MaxFolderDepth {
				truncate(fmt.Sprintf("folders nest deeper than %d levels under %s", MaxFolderDepth, p.name))
				break
			}
			if seen[f.Name] {
				continue
			}
			seen[f.Name] = true
			tree.Nodes = append(tree.Nodes, ScopeNode{
				ID: strings.TrimPrefix(f.Name, "folders/"), Kind: ScopeNodeFolder,
				Parent: p.name, DisplayName: f.DisplayName, State: f.State,
			})
			queue = append(queue, parentRef{name: f.Name, depth: p.depth + 1})
		}

		projects, err := w.listProjects(ctx, p.name)
		if err != nil {
			return nil, err
		}
		for _, pr := range projects {
			tree.Nodes = append(tree.Nodes, ScopeNode{
				ID: pr.ProjectId, Kind: ScopeNodeProject, Parent: p.name,
				DisplayName: pr.DisplayName, State: pr.State,
				Number: strings.TrimPrefix(pr.Name, "projects/"),
			})
		}
	}
	return tree, nil
}

// listFolders lists the ACTIVE folders directly under parent. Paginated by hand
// so each page is separately rate-limited and retried (see resolveProjects in
// services for why .Pages() is not used).
func (w *ScopeTreeWalker) listFolders(ctx context.Context, parent string) ([]*cloudresourcemanager.Folder, error) {
	var out []*cloudresourcemanager.Folder
	token := ""
	for page := 0; page < scopeTreeMaxPages; page++ {
		var resp *cloudresourcemanager.ListFoldersResponse
		tok := token
		if err := Retry(ctx, func() error {
			if err := w.Governor.ResourceManager.Wait(ctx); err != nil {
				return err
			}
			r, err := w.RM.Folders.List().Parent(parent).PageSize(300).PageToken(tok).Context(ctx).Do()
			if err != nil {
				return err
			}
			resp = r
			return nil
		}); err != nil {
			return nil, err
		}
		for _, f := range resp.Folders {
			if f.State != "" && f.State != "ACTIVE" {
				continue
			}
			out = append(out, f)
		}
		if resp.NextPageToken == "" {
			return out, nil
		}
		token = resp.NextPageToken
	}
	return nil, fmt.Errorf("gcp: listing folders under %s exceeded %d pages", parent, scopeTreeMaxPages)
}

// listProjects lists the ACTIVE projects whose direct parent is parent. A
// project being deleted is not part of the estate; reading it would add rows
// the next scan removes.
func (w *ScopeTreeWalker) listProjects(ctx context.Context, parent string) ([]*cloudresourcemanager.Project, error) {
	var out []*cloudresourcemanager.Project
	token := ""
	for page := 0; page < scopeTreeMaxPages; page++ {
		var resp *cloudresourcemanager.SearchProjectsResponse
		tok := token
		if err := Retry(ctx, func() error {
			if err := w.Governor.ResourceManager.Wait(ctx); err != nil {
				return err
			}
			r, err := w.RM.Projects.Search().Query("parent:" + parent).PageToken(tok).Context(ctx).Do()
			if err != nil {
				return err
			}
			resp = r
			return nil
		}); err != nil {
			return nil, err
		}
		for _, p := range resp.Projects {
			if p.State != "" && p.State != "ACTIVE" {
				continue
			}
			out = append(out, p)
		}
		if resp.NextPageToken == "" {
			return out, nil
		}
		token = resp.NextPageToken
	}
	return nil, fmt.Errorf("gcp: listing projects under %s exceeded %d pages", parent, scopeTreeMaxPages)
}
