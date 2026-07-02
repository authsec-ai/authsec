package connectoradapters

import (
	"context"
	"fmt"
)

func init() { Register(&slackAdapter{}) }

// slackAdapter implements Slack actions. Endpoints are fixed (SSRF guard).
type slackAdapter struct{}

func (a *slackAdapter) Key() string { return "slack" }

func (a *slackAdapter) Execute(ctx context.Context, cred Credential, req Request) (*Result, error) {
	switch req.ActionKey {
	case "postMessage":
		channel, err := requiredString(req.Input, "channel")
		if err != nil {
			return nil, err
		}
		text, err := requiredString(req.Input, "text")
		if err != nil {
			return nil, err
		}
		// Fixed Slack Web API endpoint; token injected as Bearer.
		return doJSON(ctx, "POST", "https://slack.com/api/chat.postMessage", cred, map[string]interface{}{
			"channel": channel,
			"text":    text,
		})
	default:
		return nil, fmt.Errorf("unknown slack action %q", req.ActionKey)
	}
}
