package connectoradapters

import (
	"context"
	"fmt"
)

func init() { Register(&githubAdapter{}) }

// githubAdapter implements GitHub actions. The repo owner/name come from typed
// input and are interpolated only into the fixed api.github.com path — the base
// host is never caller-controlled.
type githubAdapter struct{}

func (a *githubAdapter) Key() string { return "github" }

func (a *githubAdapter) Execute(ctx context.Context, cred Credential, req Request) (*Result, error) {
	switch req.ActionKey {
	case "createIssue":
		owner, err := requiredString(req.Input, "owner")
		if err != nil {
			return nil, err
		}
		repo, err := requiredString(req.Input, "repo")
		if err != nil {
			return nil, err
		}
		title, err := requiredString(req.Input, "title")
		if err != nil {
			return nil, err
		}
		if err := validatePathSegment(owner); err != nil {
			return nil, fmt.Errorf("owner: %w", err)
		}
		if err := validatePathSegment(repo); err != nil {
			return nil, fmt.Errorf("repo: %w", err)
		}
		endpoint := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", owner, repo)
		payload := map[string]interface{}{"title": title}
		if body := optionalString(req.Input, "body"); body != "" {
			payload["body"] = body
		}
		return doJSON(ctx, "POST", endpoint, cred, payload)
	default:
		return nil, fmt.Errorf("unknown github action %q", req.ActionKey)
	}
}

// validatePathSegment rejects owner/repo values that could break out of the
// fixed path (slashes, dots, whitespace) — defense in depth against path
// traversal / host confusion even though the host is hardcoded.
func validatePathSegment(s string) error {
	if s == "" {
		return fmt.Errorf("empty")
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return fmt.Errorf("invalid character %q", r)
		}
	}
	if s == "." || s == ".." {
		return fmt.Errorf("invalid segment")
	}
	return nil
}
