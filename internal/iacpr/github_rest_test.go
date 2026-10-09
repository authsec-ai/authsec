package iacpr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// fakeGitHubAPI is an in-process GitHub REST API behind an http.RoundTripper
// (no network): enough of git data, refs and pulls for the REST adapter, with
// fault injection per "METHOD path-prefix".
type fakeGitHubAPI struct {
	mu       sync.Mutex
	hosts    []string
	paths    []string
	seq      int
	commits  map[string]string // sha -> message
	refs     map[string]string // branch -> sha
	pulls    map[string]int    // branch -> number
	failOnce map[string]int    // "POST /pulls" -> status
	writes   map[string]int
}

func newFakeGitHubAPI() *fakeGitHubAPI {
	return &fakeGitHubAPI{commits: map[string]string{"base0": "initial"}, refs: map[string]string{}, pulls: map[string]int{},
		failOnce: map[string]int{}, writes: map[string]int{}}
}

func (f *fakeGitHubAPI) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts = append(f.hosts, req.URL.Scheme+"://"+req.URL.Host)
	f.paths = append(f.paths, req.URL.Path)
	p := req.URL.Path
	if i := strings.Index(p, "/repos/acme/infra"); i >= 0 {
		p = p[i+len("/repos/acme/infra"):]
	}
	var body map[string]any
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &body)
	}
	resp := func(status int, v any) (*http.Response, error) {
		raw, _ := json.Marshal(v)
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}, nil
	}
	for k, st := range f.failOnce {
		parts := strings.SplitN(k, " ", 2)
		if req.Method == parts[0] && strings.HasPrefix(p, parts[1]) {
			delete(f.failOnce, k)
			return resp(st, map[string]string{"message": "injected"})
		}
	}
	if req.Method != http.MethodGet {
		f.writes[req.Method+" "+strings.SplitN(p+"/", "/", 4)[1]+"/"+strings.SplitN(p+"/", "/", 4)[2]]++
	}
	f.seq++
	switch {
	case req.Method == http.MethodGet && p == "/pulls":
		head := req.URL.Query().Get("head")
		br := head[strings.Index(head, ":")+1:]
		if n, ok := f.pulls[br]; ok {
			return resp(200, []any{map[string]any{"number": n, "html_url": fmt.Sprintf("https://x/pull/%d", n), "head": map[string]string{"sha": f.refs[br]}}})
		}
		return resp(200, []any{})
	case req.Method == http.MethodGet && strings.HasPrefix(p, "/git/ref/heads/"):
		br := strings.TrimPrefix(p, "/git/ref/heads/")
		if sha, ok := f.refs[br]; ok {
			return resp(200, map[string]any{"object": map[string]string{"sha": sha}})
		}
		return resp(404, map[string]string{"message": "Not Found"})
	case req.Method == http.MethodGet && strings.HasPrefix(p, "/git/commits/"):
		sha := strings.TrimPrefix(p, "/git/commits/")
		msg, ok := f.commits[sha]
		if !ok {
			return resp(404, map[string]string{"message": "Not Found"})
		}
		return resp(200, map[string]any{"sha": sha, "message": msg, "tree": map[string]string{"sha": "tree-" + sha}})
	case req.Method == http.MethodPost && p == "/git/blobs":
		return resp(201, map[string]string{"sha": fmt.Sprintf("blob%d", f.seq)})
	case req.Method == http.MethodPost && p == "/git/trees":
		return resp(201, map[string]string{"sha": fmt.Sprintf("tree%d", f.seq)})
	case req.Method == http.MethodPost && p == "/git/commits":
		sha := fmt.Sprintf("c%d", f.seq)
		f.commits[sha] = body["message"].(string)
		return resp(201, map[string]string{"sha": sha})
	case req.Method == http.MethodPost && p == "/git/refs":
		br := strings.TrimPrefix(body["ref"].(string), "refs/heads/")
		if _, ok := f.refs[br]; ok {
			return resp(422, map[string]string{"message": "Reference already exists"})
		}
		f.refs[br] = body["sha"].(string)
		return resp(201, map[string]string{})
	case req.Method == http.MethodPost && p == "/pulls":
		br := body["head"].(string)
		if _, ok := f.pulls[br]; ok {
			return resp(422, map[string]string{"message": "A pull request already exists"})
		}
		f.pulls[br] = len(f.pulls) + 1
		return resp(201, map[string]any{"number": f.pulls[br], "html_url": fmt.Sprintf("https://x/pull/%d", f.pulls[br])})
	}
	return resp(404, map[string]string{"message": "unhandled " + req.Method + " " + p})
}

func restOver(api *fakeGitHubAPI) *REST {
	return &REST{HTTP: &http.Client{Transport: api}, Token: func(context.Context, RepoRef) (string, error) { return "tok", nil }}
}

func prInput(steps *[]string) PullRequestInput {
	return PullRequestInput{BaseBranch: "main", BaseSHA: "base0", Branch: "authsec/dep-1", Title: "t", Body: "b",
		CommitMessage: "AuthSec change\n\nPlan hash: sha256:p", Files: []FileChange{{Path: "iam/main.tf", After: "x"}},
		OnStep: func(_ context.Context, step, sha string) error { *steps = append(*steps, step+":"+sha); return nil }}
}

// P2 (GitHub): dying between POST git/refs and POST pulls is resumed: the
// next attempt finds the branch by name, reuses it and creates only the PR.
func TestRESTOpenPullRequestResumesAfterCrashBetweenRefAndPull(t *testing.T) {
	api := newFakeGitHubAPI()
	g := restOver(api)
	repo := RepoRef{FullName: "acme/infra", ProviderHost: "github.com"}
	var steps []string
	api.failOnce["POST /pulls"] = http.StatusBadGateway // the "crash"
	if _, err := g.OpenPullRequest(context.Background(), repo, prInput(&steps)); err == nil {
		t.Fatal("first attempt succeeded")
	}
	if len(steps) != 2 || !strings.HasPrefix(steps[0], StepRef+":") || api.refs["authsec/dep-1"] == "" {
		t.Fatalf("steps %v refs %v", steps, api.refs)
	}
	recorded := strings.TrimPrefix(steps[0], StepRef+":")
	commitsBefore, refsBefore := api.writes["POST git/commits"], api.writes["POST git/refs"]
	in := prInput(&steps)
	in.ResumeSHA = recorded
	pr, err := g.OpenPullRequest(context.Background(), repo, in)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if pr.Number != 1 || pr.HeadSHA != recorded || api.writes["POST git/commits"] != commitsBefore || api.writes["POST git/refs"] != refsBefore {
		t.Fatalf("resume re-created state: %+v writes %v", pr, api.writes)
	}
	// A third call finds the PR by branch.
	again, err := g.OpenPullRequest(context.Background(), repo, prInput(&steps))
	if err != nil || again.Number != 1 || api.writes["POST pulls/"] != 1 {
		t.Fatalf("idempotent: %+v %v %v", again, err, api.writes)
	}
	// Without a recorded commit, the branch is still recognised by its
	// commit message; a branch with a foreign commit is a conflict.
	api2 := newFakeGitHubAPI()
	api2.failOnce["POST /pulls"] = http.StatusBadGateway
	g2 := restOver(api2)
	var s2 []string
	_, _ = g2.OpenPullRequest(context.Background(), repo, prInput(&s2))
	if _, err := g2.OpenPullRequest(context.Background(), repo, prInput(&s2)); err != nil {
		t.Fatalf("resume by message: %v", err)
	}
	api3 := newFakeGitHubAPI()
	api3.commits["foreign"] = "someone else's commit"
	api3.refs["authsec/dep-1"] = "foreign"
	var s3 []string
	if _, err := restOver(api3).OpenPullRequest(context.Background(), repo, prInput(&s3)); !errors.Is(err, ErrBranchConflict) {
		t.Fatalf("foreign branch: %v", err)
	}
}

// P2 (GitHub): a GitHub Enterprise Server integration is addressed at
// https://<host>/api/v3, never at api.github.com.
func TestRESTHonoursProviderHost(t *testing.T) {
	for host, want := range map[string]string{
		"ghe.example.com": "https://ghe.example.com",
		"github.com":      "https://api.github.com",
		"":                "https://api.github.com",
	} {
		api := newFakeGitHubAPI()
		var steps []string
		if _, err := restOver(api).OpenPullRequest(context.Background(), RepoRef{FullName: "acme/infra", ProviderHost: host}, prInput(&steps)); err != nil {
			t.Fatalf("%q: %v", host, err)
		}
		for i, h := range api.hosts {
			if h != want {
				t.Fatalf("%q: request %d went to %s", host, i, h)
			}
			if host == "ghe.example.com" && !strings.HasPrefix(api.paths[i], "/api/v3/repos/") {
				t.Fatalf("GHES path %s", api.paths[i])
			}
		}
	}
	if got := APIBase("ghe.example.com", "https://api.github.com"); got != "https://ghe.example.com/api/v3" {
		t.Fatalf("APIBase %s", got)
	}
}
