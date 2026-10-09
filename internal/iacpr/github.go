package iacpr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	// ResumeSHA is the commit an earlier, interrupted attempt created and
	// the caller recorded (iga_gov_iac_change.proposed_sha while opening): a
	// branch whose head is this commit is this change's and is reused.
	ResumeSHA string
	// OnStep is called BEFORE each write GitHub keeps: StepRef (the commit
	// exists, sha known; the branch is about to be created or moved) and
	// StepPull (the branch exists at sha; the PR is about to be created).
	// The caller records its intent there, so a crash between any two
	// writes is resumed from what was recorded and what GitHub shows by
	// branch name. An error aborts before the write.
	OnStep func(ctx context.Context, step, sha string) error
}

// Steps of opening or updating a PR (PullRequestInput.OnStep).
const (
	StepRef  = "ref"
	StepPull = "pull"
)

func (in PullRequestInput) step(ctx context.Context, step, sha string) error {
	if in.OnStep == nil {
		return nil
	}
	return in.OnStep(ctx, step, sha)
}

// ErrBranchConflict: the PR branch exists with a head AuthSec did not
// create; it is never reused or overwritten.
var ErrBranchConflict = errors.New("iacpr: the branch exists with a commit AuthSec did not create")

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
	Title     string
	Body      string
	Branch    string
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
	// UpdatePullRequest re-commits the change on in.BaseSHA, moves the PR's
	// branch (in.Branch) to it and replaces the title and body.
	UpdatePullRequest(ctx context.Context, repo RepoRef, number int, in PullRequestInput) (PullRequest, error)
	// ClosePullRequest comments the reason and closes the PR unmerged.
	ClosePullRequest(ctx context.Context, repo RepoRef, number int, comment string) error
}

// APIBase is the REST API root of a GitHub host: api.github.com for
// github.com, https://<host>/api/v3 for GitHub Enterprise Server. fallback
// (REST.BaseURL) is used for github.com only, so an integration on a GHES
// host never talks to github.com.
func APIBase(providerHost, fallback string) string {
	h := strings.TrimRight(strings.TrimSpace(providerHost), "/")
	switch strings.ToLower(h) {
	case "", "github.com", "api.github.com", "https://github.com", "https://api.github.com":
		if fallback != "" {
			return strings.TrimRight(fallback, "/")
		}
		return "https://api.github.com"
	}
	if !strings.HasPrefix(h, "https://") && !strings.HasPrefix(h, "http://") {
		h = "https://" + h
	}
	return h + "/api/v3"
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
	// CrashAfter injects a crash AFTER a step's write (consumed once):
	// StepRef -- the branch was created, the PR was not (the process "died"
	// between POST git/refs and POST pulls).
	CrashAfter map[string]bool
	// Calls counts calls by method.
	Calls map[string]int
}

type fakeRepo struct {
	branches map[string]string            // branch -> commit
	commits  map[string]map[string]string // commit -> files
	messages map[string]string            // commit -> message
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
	comments []string
}

// ErrInjectedCrash is what a CrashAfter step returns.
var ErrInjectedCrash = errors.New("iacpr fake: injected crash")

// NewFake builds an empty fake.
func NewFake() *Fake {
	return &Fake{repos: map[string]*fakeRepo{}, Fail: map[string]error{}, CrashAfter: map[string]bool{}, Calls: map[string]int{}}
}

func (f *Fake) repo(name string) *fakeRepo {
	r := f.repos[name]
	if r == nil {
		r = &fakeRepo{branches: map[string]string{}, commits: map[string]map[string]string{}, messages: map[string]string{}, prs: map[int]*fakePR{},
			runs: map[string][]ApplyRun{}}
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

// OpenPullRequest implements GitHub with the REST adapter's protocol: the
// PR by branch, else the branch (reused only when it is this change's),
// else a commit, OnStep(StepRef), the branch, OnStep(StepPull), the PR.
func (f *Fake) OpenPullRequest(ctx context.Context, repo RepoRef, in PullRequestInput) (PullRequest, error) {
	if err := f.fail("OpenPullRequest"); err != nil {
		return PullRequest{}, err
	}
	r := f.repo(repo.FullName)
	for _, pr := range r.prs {
		if pr.branch == in.Branch {
			return PullRequest{Number: pr.number, URL: fakeURL(repo.FullName, pr.number), HeadSHA: r.branches[pr.branch]}, nil
		}
	}
	head, exists := r.branches[in.Branch]
	if exists {
		if !(in.ResumeSHA != "" && head == in.ResumeSHA) && r.messages[head] != in.CommitMessage {
			return PullRequest{}, fmt.Errorf("%w: %s at %s", ErrBranchConflict, in.Branch, head)
		}
	} else {
		s, err := f.commitOn(r, in)
		if err != nil {
			return PullRequest{}, err
		}
		if err := in.step(ctx, StepRef, s); err != nil {
			return PullRequest{}, err
		}
		f.Calls["CreateRef"]++
		r.branches[in.Branch] = s
		head = s
		if f.CrashAfter[StepRef] {
			delete(f.CrashAfter, StepRef)
			return PullRequest{}, ErrInjectedCrash
		}
	}
	if err := in.step(ctx, StepPull, head); err != nil {
		return PullRequest{}, err
	}
	f.Calls["CreatePull"]++
	r.next++
	pr := &fakePR{number: r.next, branch: in.Branch, base: in.BaseBranch, state: "open", title: in.Title, body: in.Body}
	r.prs[pr.number] = pr
	return PullRequest{Number: pr.number, URL: fakeURL(repo.FullName, pr.number), HeadSHA: head}, nil
}

func (f *Fake) commitOn(r *fakeRepo, in PullRequestInput) (string, error) {
	base := r.commits[in.BaseSHA]
	if base == nil {
		return "", fmt.Errorf("base commit %s not found", in.BaseSHA)
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
	r.messages[s] = in.CommitMessage
	return s, nil
}

// UpdatePullRequest implements GitHub.
func (f *Fake) UpdatePullRequest(ctx context.Context, repo RepoRef, number int, in PullRequestInput) (PullRequest, error) {
	if err := f.fail("UpdatePullRequest"); err != nil {
		return PullRequest{}, err
	}
	r := f.repo(repo.FullName)
	pr := r.prs[number]
	if pr == nil {
		return PullRequest{}, fmt.Errorf("pull request %d not found", number)
	}
	s, err := f.commitOn(r, in)
	if err != nil {
		return PullRequest{}, err
	}
	if err := in.step(ctx, StepRef, s); err != nil {
		return PullRequest{}, err
	}
	r.branches[pr.branch] = s
	pr.title, pr.body = in.Title, in.Body
	return PullRequest{Number: number, URL: fakeURL(repo.FullName, number), HeadSHA: s}, nil
}

// ClosePullRequest implements GitHub.
func (f *Fake) ClosePullRequest(_ context.Context, repo RepoRef, number int, comment string) error {
	if err := f.fail("ClosePullRequest"); err != nil {
		return err
	}
	pr := f.repo(repo.FullName).prs[number]
	if pr == nil {
		return fmt.Errorf("pull request %d not found", number)
	}
	if comment != "" {
		pr.comments = append(pr.comments, comment)
	}
	pr.state = "closed"
	return nil
}

// PRComments are the comments AuthSec left on a PR.
func (f *Fake) PRComments(repo string, number int) []string {
	if pr := f.repo(repo).prs[number]; pr != nil {
		return append([]string{}, pr.comments...)
	}
	return nil
}

// HasBranch reports whether a branch exists.
func (f *Fake) HasBranch(repo, branch string) bool {
	_, ok := f.repo(repo).branches[branch]
	return ok
}

// PRState is a PR's state (open | closed).
func (f *Fake) PRState(repo string, number int) string {
	if pr := f.repo(repo).prs[number]; pr != nil {
		return pr.state
	}
	return ""
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
	st := PullRequestState{Number: number, Title: pr.title, Body: pr.body, Branch: pr.branch, State: pr.state, Merged: pr.merged, MergedSHA: pr.mergeSHA, MergedAt: pr.mergedAt,
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
	// BaseURL is the github.com API root (default https://api.github.com);
	// a repository on a GitHub Enterprise Server host (RepoRef.ProviderHost)
	// is always addressed at https://<host>/api/v3 (APIBase).
	BaseURL string
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
	req, err := http.NewRequestWithContext(ctx, method, APIBase(repo.ProviderHost, g.BaseURL)+p, rd)
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
// then the PR). It is crash-safe: every state GitHub keeps is findable by
// the branch name, and the caller records intent before each write
// (in.OnStep). A run that died after POST git/refs and before POST pulls is
// resumed by the next call: the PR is looked up by branch, then the branch
// ref; a branch whose head is the recorded commit (in.ResumeSHA) or a commit
// with this change's message is reused, and only the PR is created. A
// branch AuthSec did not create is ErrBranchConflict, never overwritten.
func (g *REST) OpenPullRequest(ctx context.Context, repo RepoRef, in PullRequestInput) (PullRequest, error) {
	if pr, ok, err := g.findPull(ctx, repo, in.Branch); err != nil || ok {
		return pr, err
	}
	head, exists, err := g.branchHead(ctx, repo, in.Branch)
	if err != nil {
		return PullRequest{}, err
	}
	if exists {
		if err := g.ownBranch(ctx, repo, head, in); err != nil {
			return PullRequest{}, err
		}
	} else {
		sha, err := g.commitFiles(ctx, repo, in.BaseSHA, in.CommitMessage, in.Files)
		if err != nil {
			return PullRequest{}, err
		}
		if err := in.step(ctx, StepRef, sha); err != nil {
			return PullRequest{}, err
		}
		status, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/git/refs",
			map[string]string{"ref": "refs/heads/" + in.Branch, "sha": sha}, nil)
		if err != nil && status != http.StatusUnprocessableEntity {
			return PullRequest{}, err
		}
		if err != nil { // created meanwhile (a concurrent or replayed attempt)
			if head, exists, err = g.branchHead(ctx, repo, in.Branch); err != nil || !exists {
				return PullRequest{}, fmt.Errorf("github: branch %s: %v", in.Branch, err)
			}
			if err := g.ownBranch(ctx, repo, head, in); err != nil {
				return PullRequest{}, err
			}
		} else {
			head = sha
		}
	}
	if err := in.step(ctx, StepPull, head); err != nil {
		return PullRequest{}, err
	}
	var pr struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	status, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/pulls",
		map[string]any{"title": in.Title, "head": in.Branch, "base": in.BaseBranch, "body": in.Body}, &pr)
	if err != nil {
		if status == http.StatusUnprocessableEntity { // "A pull request already exists"
			if found, ok, ferr := g.findPull(ctx, repo, in.Branch); ferr == nil && ok {
				return found, nil
			}
		}
		return PullRequest{}, err
	}
	return PullRequest{Number: pr.Number, URL: pr.HTMLURL, HeadSHA: head}, nil
}

func (g *REST) findPull(ctx context.Context, repo RepoRef, branch string) (PullRequest, bool, error) {
	owner := strings.SplitN(repo.FullName, "/", 2)[0]
	var existing []struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
		Head    struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/pulls?state=all&head="+url.QueryEscape(owner+":"+branch), nil, &existing); err != nil {
		return PullRequest{}, false, err
	}
	if len(existing) == 0 {
		return PullRequest{}, false, nil
	}
	return PullRequest{Number: existing[0].Number, URL: existing[0].HTMLURL, HeadSHA: existing[0].Head.SHA}, true, nil
}

// branchHead reads refs/heads/<branch>; exists is false on 404.
func (g *REST) branchHead(ctx context.Context, repo RepoRef, branch string) (string, bool, error) {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	status, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/git/ref/heads/"+escapePath(branch), nil, &ref)
	if status == http.StatusNotFound {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return ref.Object.SHA, true, nil
}

// ownBranch: the branch's head is the commit an earlier attempt recorded,
// or a commit carrying this change's message (the attempt died before it
// could record it).
func (g *REST) ownBranch(ctx context.Context, repo RepoRef, head string, in PullRequestInput) error {
	if in.ResumeSHA != "" && head == in.ResumeSHA {
		return nil
	}
	var c struct {
		Message string `json:"message"`
	}
	if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/git/commits/"+head, nil, &c); err != nil {
		return err
	}
	if c.Message != in.CommitMessage {
		return fmt.Errorf("%w: %s at %s", ErrBranchConflict, in.Branch, head)
	}
	return nil
}

// commitFiles writes the files as one commit on parent (blobs, tree,
// commit); nothing is visible on a branch yet.
func (g *REST) commitFiles(ctx context.Context, repo RepoRef, parent, message string, files []FileChange) (string, error) {
	var base struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if _, err := g.do(ctx, repo, http.MethodGet, repoPath(repo)+"/git/commits/"+parent, nil, &base); err != nil {
		return "", err
	}
	type treeEntry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	}
	var tree []treeEntry
	for _, fc := range files {
		var blob struct {
			SHA string `json:"sha"`
		}
		if _, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/git/blobs",
			map[string]string{"content": fc.After, "encoding": "utf-8"}, &blob); err != nil {
			return "", err
		}
		tree = append(tree, treeEntry{Path: fc.Path, Mode: "100644", Type: "blob", SHA: blob.SHA})
	}
	var nt struct {
		SHA string `json:"sha"`
	}
	if _, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/git/trees", map[string]any{"base_tree": base.Tree.SHA, "tree": tree}, &nt); err != nil {
		return "", err
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if _, err := g.do(ctx, repo, http.MethodPost, repoPath(repo)+"/git/commits",
		map[string]any{"message": message, "tree": nt.SHA, "parents": []string{parent}}, &commit); err != nil {
		return "", err
	}
	return commit.SHA, nil
}

// UpdatePullRequest implements GitHub: the change is re-committed on
// in.BaseSHA (the base branch's current head), the PR branch is moved to it
// and the title and body are replaced.
func (g *REST) UpdatePullRequest(ctx context.Context, repo RepoRef, number int, in PullRequestInput) (PullRequest, error) {
	sha, err := g.commitFiles(ctx, repo, in.BaseSHA, in.CommitMessage, in.Files)
	if err != nil {
		return PullRequest{}, err
	}
	if err := in.step(ctx, StepRef, sha); err != nil {
		return PullRequest{}, err
	}
	if _, err := g.do(ctx, repo, http.MethodPatch, repoPath(repo)+"/git/refs/heads/"+escapePath(in.Branch),
		map[string]any{"sha": sha, "force": true}, nil); err != nil {
		return PullRequest{}, err
	}
	var pr struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	if _, err := g.do(ctx, repo, http.MethodPatch, fmt.Sprintf("%s/pulls/%d", repoPath(repo), number),
		map[string]any{"title": in.Title, "body": in.Body}, &pr); err != nil {
		return PullRequest{}, err
	}
	return PullRequest{Number: number, URL: pr.HTMLURL, HeadSHA: sha}, nil
}

// ClosePullRequest implements GitHub: a comment with the reason, then the PR
// is closed unmerged.
func (g *REST) ClosePullRequest(ctx context.Context, repo RepoRef, number int, comment string) error {
	if comment != "" {
		if _, err := g.do(ctx, repo, http.MethodPost, fmt.Sprintf("%s/issues/%d/comments", repoPath(repo), number),
			map[string]string{"body": comment}, nil); err != nil {
			return err
		}
	}
	_, err := g.do(ctx, repo, http.MethodPatch, fmt.Sprintf("%s/pulls/%d", repoPath(repo), number), map[string]string{"state": "closed"}, nil)
	return err
}

// PullRequestState implements GitHub.
func (g *REST) PullRequestState(ctx context.Context, repo RepoRef, number int) (PullRequestState, error) {
	var pr struct {
		Title          string     `json:"title"`
		Body           string     `json:"body"`
		State          string     `json:"state"`
		Merged         bool       `json:"merged"`
		MergeCommitSHA string     `json:"merge_commit_sha"`
		MergedAt       *time.Time `json:"merged_at"`
		Head           struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
	}
	p := fmt.Sprintf("%s/pulls/%d", repoPath(repo), number)
	if _, err := g.do(ctx, repo, http.MethodGet, p, nil, &pr); err != nil {
		return PullRequestState{}, err
	}
	st := PullRequestState{Number: number, Title: pr.Title, Body: pr.Body, Branch: pr.Head.Ref, State: pr.State, Merged: pr.Merged,
		MergedAt: pr.MergedAt, HeadSHA: pr.Head.SHA}
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
