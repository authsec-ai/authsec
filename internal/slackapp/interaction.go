package slackapp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Interaction is the part of a Slack interaction payload AuthSec reads
// (type block_actions; https://api.slack.com/reference/interaction-payloads/block-actions).
type Interaction struct {
	Type string `json:"type"`
	Team struct {
		ID     string `json:"id"`
		Domain string `json:"domain"`
	} `json:"team"`
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
		TeamID   string `json:"team_id"`
	} `json:"user"`
	APIAppID  string `json:"api_app_id"`
	Container struct {
		Type        string `json:"type"`
		MessageTS   string `json:"message_ts"`
		ChannelID   string `json:"channel_id"`
		IsEphemeral bool   `json:"is_ephemeral"`
	} `json:"container"`
	Channel struct {
		ID string `json:"id"`
	} `json:"channel"`
	Message struct {
		TS string `json:"ts"`
	} `json:"message"`
	ResponseURL string   `json:"response_url"`
	TriggerID   string   `json:"trigger_id"`
	Actions     []Action `json:"actions"`
	State       struct {
		Values map[string]map[string]StateValue `json:"values"`
	} `json:"state"`
}

// Action is one element interaction.
type Action struct {
	ActionID string `json:"action_id"`
	BlockID  string `json:"block_id"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	ActionTS string `json:"action_ts"`
}

// Option is a selected option.
type Option struct {
	Value string `json:"value"`
}

// StateValue is the current value of one input element of the message.
type StateValue struct {
	Type            string   `json:"type"`
	Value           string   `json:"value"`
	SelectedDate    string   `json:"selected_date"`
	SelectedOptions []Option `json:"selected_options"`
	SelectedOption  *Option  `json:"selected_option"`
}

// Interaction types.
const TypeBlockActions = "block_actions"

// ErrPayload is a body that is not a Slack interaction.
var ErrPayload = errors.New("not a Slack interaction payload")

// ParseInteraction decodes the form-encoded body Slack posts
// (payload=<json>). It does not verify anything: call Verify first.
func ParseInteraction(body []byte) (*Interaction, error) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	raw := form.Get("payload")
	if raw == "" {
		return nil, fmt.Errorf("%w: no payload field", ErrPayload)
	}
	var in Interaction
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	if in.Type == "" {
		return nil, fmt.Errorf("%w: no type", ErrPayload)
	}
	return &in, nil
}

// TeamID is the Slack team the acting user belongs to.
func (in *Interaction) TeamID() string {
	if in.Team.ID != "" {
		return in.Team.ID
	}
	return in.User.TeamID
}

// MessageTS is the ts of the message whose element was used.
func (in *Interaction) MessageTS() string {
	if in.Container.MessageTS != "" {
		return in.Container.MessageTS
	}
	return in.Message.TS
}

// Text returns the plain-text input of the given block (BlockNote etc.).
func (in *Interaction) Text(block string) string {
	for _, v := range in.State.Values[block] {
		if v.Value != "" {
			return strings.TrimSpace(v.Value)
		}
	}
	return ""
}

// Date returns the datepicker value of the given block ("" when unset).
func (in *Interaction) Date(block string) string {
	for _, v := range in.State.Values[block] {
		if v.SelectedDate != "" {
			return v.SelectedDate
		}
	}
	return ""
}

// Selected returns the selected option values of the given block
// (checkboxes, multi-select or a single select).
func (in *Interaction) Selected(block string) []string {
	var out []string
	for _, v := range in.State.Values[block] {
		for _, o := range v.SelectedOptions {
			out = append(out, o.Value)
		}
		if v.SelectedOption != nil && v.SelectedOption.Value != "" {
			out = append(out, v.SelectedOption.Value)
		}
	}
	return out
}

var actionTSRe = regexp.MustCompile(`^[0-9]{1,12}\.[0-9]{1,9}$`)

// ValidActionTS reports whether ts has Slack's "<seconds>.<fraction>" form
// (what the replay check compares numerically).
func ValidActionTS(ts string) bool { return actionTSRe.MatchString(ts) }

/* ------------------------------ button values ----------------------------- */

// ButtonValue is what an AuthSec button carries: the notification it
// belongs to and, for approval buttons, the digest of the approval hashes
// the message showed (so a click binds what the approver saw).
type ButtonValue struct {
	Notification string `json:"n"`
	Digest       string `json:"d,omitempty"`
}

// Encode renders the value (Slack allows 2000 characters; this is < 150).
func (v ButtonValue) Encode() string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeButtonValue parses a value written by Encode.
func DecodeButtonValue(s string) (ButtonValue, error) {
	var v ButtonValue
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return v, fmt.Errorf("%w: button value", ErrPayload)
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Notification == "" {
		return v, fmt.Errorf("%w: button value", ErrPayload)
	}
	return v, nil
}
