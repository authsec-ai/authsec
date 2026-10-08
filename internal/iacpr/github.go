package iacpr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// The pull-request adapter (§8.11 J2) over the customer's GitHub App
// installation -- the same App and installation the GitHub discovery source
// already uses (iga_integrations). It needs contents: write and
// pull_requests: write, which the App requests only when a customer maps an
// IaC source (services/iga_gov_iac_source_service.go records the request).
//
// GitHub is an interface so every test runs against the in-memory Fake; the
// REST implementation is the production one. No test calls GitHub.

// RepoRef names a repository through an installation.
type RepoRef struct {
	WorkspaceID    string
	IntegrationID  string
	InstallationID string
	ProviderHost   string
	FullName       string // owner/repo
}

// Snapshot is a directory read at one commit.
type Snapshot struct {
	CommitSHA string
	Files     map[string]string
}

// PullRequestInput opens one change.
type PullRequestInput struct {
	BaseBranch    string
	BaseSHA       string // the commit the change was rendered against
	Branch        string
	Title         string
	Body          string
	CommitMessage string
	Files         []FileChange
}

// PullRequest is an opened PR.
type PullRequest struct {
	Number  int    `json:"number"`
	URL     string `json:"url"`
	HeadSHA string `json:"head_sha"`
}

// ApplyRun is a check run or deployment the repository reports for a
// commit (the customer's pipeline; AuthSec shows it and does not depend on
// it, §8.11).
type ApplyRun struct {
	Ref        string `json:"ref"` // "check_run:<id>" | "deployment:<id>"
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion,omitempty"`
}

// PullRequestState is a PR as GitHub reports it now.
type PullRequestState struct {
	Number    int
	State     string // open | closed
	Merged    bool
	MergedSHA string
	MergedAt  *time.Time
	HeadSHA   string
	// FirstApprovalSHA is the head commit of the first APPROVED review
	// (iga_gov_iac_change.reviewed_sha).
	FirstApprovalSHA string
	// ApplyRuns are reported for MergedSHA when merged.
	ApplyRuns []ApplyRun
}

// GitHub is the adapter.
type GitHub interface {
	// ReadDirectory reads the regular files directly under dir at ref.
	ReadDirectory(ctx context.Context, repo RepoRef, ref, dir string) (Snapshot, error)
	// OpenPullRequest commits the files on a new branch from BaseSHA and
	// opens a PR to BaseBranch. Idempotent on Branch: a PR already open (or
	// closed) for the branch is returned, never a second one.
	OpenPullRequest(ctx context.Context, repo RepoRef, in PullRequestInput) (PullRequest, error)
	// PullRequestState reads a PR, its first approving review and, when
	// merged, the runs reported for the merge commit.
	PullRequestState(ctx context.Context, repo RepoRef, number int) (PullRequestState, error)
}

// Permissions the App needs for J2 (requested when an IaC source is mapped).
var RequiredPermissions = map[string]string{"contents": "write", "pull_requests": "write"}

// MissingPermissions lists the J2 permissions a granted set lacks.
func MissingPermissions(granted map[string]string) []string {
	var out []string
	for k, v := range RequiredPermissions {
		if granted[k] != v && !(v == "read" && granted[k] == "write") {
			out = append(out, k+":"+v)
		}
	}
	sort.Strings(out)
	return out
}

/* ---------------------------------- fake ---------------------------------- */

// Fake is an in-memory GitHub for tests: repositories, branches, commits,
// pull requests, reviews, merges and check runs.
type Fake struct {
	repos map[string]*fakeRepo
	seq   int
	// Fail makes the next call of a method fail (consumed once).
	Fail map[string]error
	// Calls counts calls by method.
	Calls map[string]int
}

type fakeRepo struct {
	branches map[string]string            // branch -> commit
	commits  map[string]map[string]string // commit -> files
	prs      map[int]*fakePR
	runs     map[string][]ApplyRun // commit -> runs
	next     int
}

type fakePR struct {
	number   int
	branch   string
	base     string
	state    string
	merged   bool
	mergeSHA string
	mergedAt *time.Time
	reviews  []string // head SHAs of approving reviews
	title    string
	body     string
}

// NewFake builds an empty fake.
func NewFake() *Fake {
	return &Fake{repos: map[string]*fakeRepo{}, Fail: map[string]error{}, Calls: map[string]int{}}
}

func (f *Fake) repo(name string) *fakeRepo {
	r := f.repos[name]
	if r == nil {
		r = &fakeRepo{branches: map[string]string{}, commits: map[string]map[string]string{}, prs: map[int]*fakePR{}, runs: map[string][]ApplyRun{}}
		f.repos[name] = r
	}
	return r
}

func (f *Fake) sha() string {
	f.seq++
	return fmt.Sprintf("%040x", f.seq)
}

func (f *Fake) fail(m string) error {
	f.Calls[m]++
	if err, ok := f.Fail[m]; ok {
		delete(f.Fail, m)
		return err
	}
	return nil
}

// Commit writes files (nil content deletes) on a branch and returns the
// new head commit.
func (f *Fake) Commit(repo, branch string, files map[string]*string) string {
	r := f.repo(repo)
	cur := map[string]string{}
	for k, v := range r.commits[r.branches[branch]] {
		cur[k] = v
	}
	for p, c := range files {
		if c == nil {
			delete(cur, p)
		} else {
			cur[p] = *c
		}
	}
	s := f.sha()
	r.commits[s] = cur
	r.branches[branch] = s
	return s
}

// Seed writes files on a branch.
func (f *Fake) Seed(repo, branch string, files map[string]string) string {
	m := map[string]*string{}
	for k, v := range files {
		v := v
		m[k] = &v
	}
	return f.Commit(repo, branch, m)
}

// File reads a file at a branch head.
func (f *Fake) File(repo, branch, p string) (string, bool) {
	r := f.repo(repo)
	v, ok := r.commits[r.branches[branch]][p]
	return v, ok
}

// Head is a branch's head commit.
func (f *Fake) Head(repo, branch string) string { return f.repo(repo).branches[branch] }

// PRFiles returns the files changed on a PR's branch relative to its base
// commit at open time (the whole head tree for simplicity of assertions).
func (f *Fake) PRFile(repo string, number int, p string) (string, bool) {
	r := f.repo(repo)
	pr := r.prs[number]
	if pr == nil {
		return "", false
	}
	v, ok := r.commits[r.branches[pr.branch]][p]
	return v, ok
}

// PRBody is a PR's title and body.
func (f *Fake) PRBody(repo string, number int) (string, string) {
	pr := f.repo(repo).prs[number]
	if pr == nil {
		return "", ""
	}
	return pr.title, pr.body
}

// PushToPR adds a commit to the PR's branch (the head moves after review).
func (f *Fake) PushToPR(repo string, number int, files map[string]string) string {
	return f.Seed(repo, f.repo(repo).prs[number].branch, files)
}

// Approve records an approving review at the PR's current head.
func (f *Fake) Approve(repo string, number int) {
	r := f.repo(repo)
	pr := r.prs[number]
	pr.reviews = append(pr.reviews, r.branches[pr.branch])
}

// Merge merges a PR: the base branch gets the head's tree in a new commit.
func (f *Fake) Merge(repo string, number int, at time.Time) string {
	r := f.repo(repo)
	pr := r.prs[number]
	head := r.commits[r.branches[pr.branch]]
	cp := map[string]string{}
	for k, v := range head {
		cp[k] = v
	}
	s := f.sha()
	r.commits[s] = cp
	r.branches[pr.base] = s
	pr.state, pr.merged, pr.mergeSHA = "closed", true, s
	t := at.UTC()
	pr.mergedAt = &t
	return s
}

// Close closes a PR without merging.
func (f *Fake) Close(repo string, number int) { f.repo(repo).prs[number].state = "closed" }

// AddRun reports a check run or deployment for a commit.
func (f *Fake) AddRun(repo, sha string, run ApplyRun) {
	r := f.repo(repo)
	r.runs[sha] = append(r.runs[sha], run)
}

// PRCount is the number of PRs opened on a repository.
func (f *Fake) PRCount(repo string) int { return len(f.repo(repo).prs) }

// ReadDirectory implements GitHub.
func (f *Fake) ReadDirectory(_ context.Context, repo RepoRef, ref, dir string) (Snapshot, error) {
	if err := f.fail("ReadDirectory"); err != nil {
		return Snapshot{}, err
	}
	r := f.repo(repo.FullName)
	sha := r.branches[ref]
	if sha == "" {
		if _, ok := r.commits[ref]; ok {
			sha = ref
		} else {
			return Snapshot{}, fmt.Errorf("ref %s not found", ref)
		}
	}
	dir = strings.Trim(dir, "/")
	out := Snapshot{CommitSHA: sha, Files: map[string]string{}}
	for p, c := range r.commits[sha] {
		if path.Dir(p) == dir || (dir == "" && !strings.Contains(p, "/")) {
			out.Files[p] = c
		}
	}
	return out, nil
}

// OpenPullRequest implements GitHub.
func (f *Fake) OpenPullRequest(_ context.Context, repo RepoRef, in PullRequestInput) (PullRequest, error) {
	if err := f.fail("OpenPullRequest"); err != nil {
		return PullRequest{}, err
	}
	r := f.repo(repo.FullName)
	for _, pr := range r.prs {
		if pr.branch == in.Branch {
			return PullRequest{Number: pr.number, URL: fakeURL(repo.FullName, pr.number), HeadSHA: r.branches[pr.branch]}, nil
		}
	}
	base := r.commits[in.BaseSHA]
	if base == nil {
		return PullRequest{}, fmt.Errorf("base commit %s not found", in.BaseSHA)
	}
	files := map[string]string{}
	for k, v := range base {
		files[k] = v
	}
	for _, fc := range in.Files {
		files[fc.Path] = fc.After
	}
	s := f.sha()
	r.commits[s] = files
	r.branches[in.Branch] = s
	r.next++
	pr := &fakePR{number: r.next, branch: in.Branch, base: in.BaseBranch, state: "open", title: in.Title, body: in.Body}
	r.prs[pr.number] = pr
	return PullRequest{Number: pr.number, URL: fakeURL(repo.FullName, pr.number), HeadSHA: s}, nil
}

// PullRequestState implements GitHub.
func (f *Fake) PullRequestState(_ context.Context, repo RepoRef, number int) (PullRequestState, error) {
	if err := f.fail("PullRequestState"); err != nil {
		return PullRequestState{}, err
	}
	r := f.repo(repo.FullName)
	pr := r.prs[number]
	if pr == nil {
		return PullRequestState{}, fmt.Errorf("pull request %d not found", number)
	}
	st := PullRequestState{Number: number, State: pr.state, Merged: pr.merged, MergedSHA: pr.mergeSHA, MergedAt: pr.mergedAt,
		HeadSHA: r.branches[pr.branch]}
	if len(pr.reviews) > 0 {
		st.FirstApprovalSHA = pr.reviews[0]
	}
	if pr.merged {
		st.ApplyRuns = append(st.ApplyRuns, r.runs[pr.mergeSHA]...)
	}
	return st, nil
}

func fakeURL(repo string, n int) string {
	return fmt.Sprintf("https://github.example/%s/pull/%d", repo, n)
}

/* ---------------------------------- REST ---------------------------------- */

// REST is the production adapter over GitHub's REST API with an installation
// token. It is not exercised by tests against GitHub (no real calls); its
// transport errors are returned as they are.
type REST struct {
	BaseURL string // https://api.github.com, or a GHES API root
	HTTP    *http.Client
	// Token mints an installation token for the repository's installation.
	Token func(ctx context.Context, repo RepoRef) (string, error)
	// MaxFiles bounds a directory read (a mapped IaC directory, not a tree).
	MaxFiles int
}

func (g *REST) do(ctx context.Context, repo RepoRef, method, p string, body any, out any) (int, error) {
	tok, err := g.Token(ctx, repo)
	if err != nil {
		return 0, fmt.Errorf("github token: %w", err)
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	base := g.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+p, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := g.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("github %s %s: %d %s", method, p, resp.StatusCode, strings.TrimSpace(string(raw[:min(len(raw), 300)])))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func repoPath(repo RepoRef) string {
	parts := strings.SplitN(repo.FullName, "/", 2)
	if len(parts) != 2 {
		return "/repos/" + url.PathEscape(repo.FullName)
	}
	return "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
}

// ReadDirectory implements GitHub.
func (g *REST) ReadDirectory(ctx context.Context, repo RepoRef, ref, dir string) (Snapshot, error) {
	var commit struct {
		SHA string `json:"sha"`
	}
	if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/commits/"+url.PathEscape(ref), nil, &commit); err != nil {
		return Snapshot{}, err
	}
	var entries []struct {
		Type string `json:"type"`
		Path string `json:"path"`
		Size int    `json:"size"`
	}
	dir = strings.Trim(dir, "/")
	if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/contents/"+escapePath(dir)+"?ref="+url.QueryEscape(commit.SHA), nil, &entries); err != nil {
		return Snapshot{}, err
	}
	max := g.MaxFiles
	if max <= 0 {
		max = 200
	}
	out := Snapshot{CommitSHA: commit.SHA, Files: map[string]string{}}
	for _, e := range entries {
		if e.Type != "file" || e.Size > 1<<20 {
			continue
		}
		if len(out.Files) >= max {
			return Snapshot{}, fmt.Errorf("%s has more than %d files", dir, max)
		}
		var f struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}
		if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/contents/"+escapePath(e.Path)+"?ref="+url.QueryEscape(commit.SHA), nil, &f); err != nil {
			return Snapshot{}, err
		}
		b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
		if err != nil {
			return Snapshot{}, fmt.Errorf("%s: %w", e.Path, err)
		}
		out.Files[e.Path] = string(b)
	}
	return out, nil
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// OpenPullRequest implements GitHub (git data API: blobs, tree, commit, ref;
// then the PR).
func (g *REST) OpenPullRequest(ctx context.Context, repo RepoRef, in PullRequestInput) (PullRequest, error) {
	owner := strings.SplitN(repo.FullName, "/", 2)[0]
	var existing []struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		Head    struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/pulls?state=all&head="+url.QueryEscape(owner+":"+in.Branch), nil, &existing); err != nil {
		return PullRequest{}, err
	}
	if len(existing) > 0 {
		return PullRequest{Number: existing[0].Number, URL: existing[0].HTMLURL, HeadSHA: existing[0].Head.SHA}, nil
	}
	var base struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/git/commits/"+in.BaseSHA, nil, &base); err != nil {
		return PullRequest{}, err
	}
	type treeEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	var tree []treeEntry
	for _, fc := range in.Files {
		var blob struct {
			SHA string `json:"sha"`
		}
		if _, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/git/blobs",
			map[string]string{"content": fc.After, "encoding": "utf-8"}, &blob); err != nil {
			return PullRequest{}, err
		}
		tree = append(tree, treeEntry{Path: fc.Path, Mode: "100644", Type: "blob", SHA: blob.SHA})
	}
	var nt struct {
		SHA string `json:"sha"`
	}
	if _, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/git/trees", map[string]any{"base_tree": base.Tree.SHA, "tree": tree}, &nt); err != nil {
		return PullRequest{}, err
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if _, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/git/commits",
		map[string]any{"message": in.CommitMessage, "tree": nt.SHA, "parents": []string{in.BaseSHA}}, &commit); err != nil {
		return PullRequest{}, err
	}
	if _, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/git/refs",
		map[string]string{"ref": "refs/heads/" + in.Branch, "sha": commit.SHA}, nil); err != nil {
		return PullRequest{}, err
	}
	var pr struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if _, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/pulls",
		map[string]any{"title": in.Title, "head": in.Branch, "base": in.BaseBranch, "body": in.Body}, &pr); err != nil {
		return PullRequest{}, err
	}
	return PullRequest{Number: pr.Number, URL: pr.HTMLURL, HeadSHA: commit.SHA}, nil
}

// PullRequestState implements GitHub.
func (g *REST) PullRequestState(ctx context.Context, repo RepoRef, number int) (PullRequestState, error) {
	var pr struct {
		State          string     `json:"state"`
		Merged         bool       `json:"merged"`
		MergeCommitSHA string     `json:"merge_commit_sha"`
		MergedAt       *time.Time `json:"merged_at"`
		Head           struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	p := fmt.Sprintf("%s/pulls/%d", repoPath(repo), number)
	if _, err := g.do(ctx, repo, http.MethodGet, p, nil, &pr); err != nil {
		return PullRequestState{}, err
	}
	st := PullRequestState{Number: number, State: pr.State, Merged: pr.Merged, MergedAt: pr.MergedAt, HeadSHA: pr.Head.SHA}
	if pr.Merged {
		st.MergedSHA = pr.MergeCommitSHA
	}
	var reviews []struct {
		State    string `json:"state"`
		CommitID string `json:"commit_id"`
	}
	if _, err := g.do(ctx, repo, http.MethodGet, p+"/reviews?per_page=100", nil, &reviews); err != nil {
		return PullRequestState{}, err
	}
	for _, r := range reviews {
		if r.State == "APPROVED" {
			st.FirstApprovalSHA = r.CommitID
			break
		}
	}
	if st.MergedSHA != "" {
		var runs struct {
			CheckRuns []struct {
				ID         int64  `json:"id"`
				Name       string `json:"name"`
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
			} `json:"check_runs"`
		}
		if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/commits/"+st.MergedSHA+"/check-runs", nil, &runs); err == nil {
			for _, r := range runs.CheckRuns {
				st.ApplyRuns = append(st.ApplyRuns, ApplyRun{Ref: fmt.Sprintf("check_run:%d", r.ID), Name: r.Name, Status: r.Status, Conclusion: r.Conclusion})
			}
		}
		var deps []struct {
			ID          int64  `json:"id"`
			Environment string `json:"environment"`
		}
		if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/deployments?sha="+st.MergedSHA, nil, &deps); err == nil {
			for _, d := range deps {
				st.ApplyRuns = append(st.ApplyRuns, ApplyRun{Ref: fmt.Sprintf("deployment:%d", d.ID), Name: d.Environment, Status: "created"})
			}
		}
	}
	return st, nil
}
