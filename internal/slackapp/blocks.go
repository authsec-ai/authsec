package slackapp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Block Kit messages (SPEC-iga-phase3-policy.md §9.3 S4, S6 and the copy
// rules of §9.7). A Message is what chat.postMessage and a response_url
// accept: a fallback text and blocks.

// Message is a Slack message.
type Message struct {
	Text            string  `json:"text"`
	Blocks          []Block `json:"blocks,omitempty"`
	ResponseType    string  `json:"response_type,omitempty"`
	ReplaceOriginal bool    `json:"replace_original,omitempty"`
}

// Block is one Block Kit block.
type Block = map[string]any

// Action ids of AuthSec's interactive elements.
const (
	ActionApprove       = "approve"
	ActionReject        = "reject"
	ActionAcknowledge   = "acknowledge"
	ActionRetain        = "retain"
	ActionObject        = "object"
	ActionReportProblem = "report_problem"
	ActionWorking       = "working"
	// ActionOpen is a link button: Slack still posts an interaction for it,
	// which is acknowledged and ignored.
	ActionOpen = "open"
)

// Block ids of the message inputs an action reads from state.values.
const (
	BlockNote          = "note"
	BlockConfirmations = "confirmations"
	BlockRetainService = "retain_services"
	BlockReviewBy      = "review_by"
)

// Copy (§9.3 S6 "After a click", §9.7). Refusals name what to do next.
const (
	CopyAuthored        = "You authored this version; another approver must decide."
	CopyLinkAccount     = "Link your Slack account to AuthSec first."
	CopyPlanChanged     = "The plan changed — open AuthSec to review the new version."
	CopyAcceptInAuthSec = "Residuals and evidence gaps are accepted item by item in AuthSec; this version cannot be approved from Slack."
	CopyNotApprover     = "You do not have permission to approve policy versions in AuthSec."
	CopyNotMember       = "You are not an active member of this AuthSec workspace."
	CopyNotOwner        = "Only an owner asked in this review can respond."
	CopyTryAuthSec      = "This could not be done from Slack — open AuthSec."
)

func text(t string) map[string]any {
	return map[string]any{"type": "plain_text", "text": t, "emoji": false}
}
func mrkdwn(t string) map[string]any {
	return map[string]any{"type": "mrkdwn", "text": t}
}

func section(t string) Block { return Block{"type": "section", "text": mrkdwn(t)} }

func header(t string) Block {
	if len(t) > 150 {
		t = t[:147] + "..."
	}
	return Block{"type": "header", "text": text(t)}
}

func contextLine(t string) Block {
	return Block{"type": "context", "elements": []any{mrkdwn(t)}}
}

// Escape makes s safe inside mrkdwn (&, <, > are Slack's control characters).
func Escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func button(actionID, label, value, style string) map[string]any {
	b := map[string]any{"type": "button", "action_id": actionID, "text": text(label), "value": value}
	if style != "" {
		b["style"] = style
	}
	return b
}

func linkButton(label, url string) map[string]any {
	return map[string]any{"type": "button", "action_id": ActionOpen, "text": text(label), "url": url}
}

func actions(blockID string, elems ...map[string]any) Block {
	out := make([]any, 0, len(elems))
	for _, e := range elems {
		out = append(out, e)
	}
	return Block{"type": "actions", "block_id": blockID, "elements": out}
}

func noteInput(label, placeholder string) Block {
	return Block{"type": "input", "block_id": BlockNote, "optional": true, "label": text(label),
		"element": map[string]any{"type": "plain_text_input", "action_id": "value", "multiline": true,
			"placeholder": text(placeholder)}}
}

func options(items []LabeledValue) []any {
	out := make([]any, 0, len(items))
	for _, it := range items {
		l := it.Label
		if len(l) > 75 {
			l = l[:72] + "..."
		}
		out = append(out, map[string]any{"text": text(l), "value": it.Value})
	}
	return out
}

// LabeledValue is an option.
type LabeledValue struct {
	Label string
	Value string
}

/* ----------------------------- approval request ---------------------------- */

// ApprovalRequest is §9.3 S6's Slack approval message.
type ApprovalRequest struct {
	PolicyName  string
	VersionNo   int
	Summary     []string // "Removes 10 AWS services from RefundTaskRole; …"
	RequestedBy string
	// Residuals and Gaps are the items acceptance needs (labels). Either
	// non-empty: no Approve button (§9.3: acceptance is item by item in
	// the console).
	Residuals []string
	Gaps      []string
	// Link opens the version in AuthSec ("" when no console URL is known).
	Link string
	// Value is the encoded ButtonValue (notification + hash digest).
	Value string
}

// Approvable reports whether the message offers Approve.
func (r ApprovalRequest) Approvable() bool { return len(r.Residuals) == 0 && len(r.Gaps) == 0 }

// BuildApprovalRequest renders r.
func BuildApprovalRequest(r ApprovalRequest) Message {
	title := fmt.Sprintf("Approval requested: %s (v%d)", r.PolicyName, r.VersionNo)
	blocks := []Block{header(title)}
	var b strings.Builder
	for _, l := range r.Summary {
		b.WriteString(Escape(l) + "\n")
	}
	if r.RequestedBy != "" {
		b.WriteString("Requested by " + Escape(r.RequestedBy) + "\n")
	}
	if s := strings.TrimSpace(b.String()); s != "" {
		blocks = append(blocks, section(s))
	}
	if !r.Approvable() {
		var lines []string
		if n := len(r.Residuals); n > 0 {
			lines = append(lines, fmt.Sprintf("*%d residual%s to accept* (%s)", n, plural(n), Escape(strings.Join(r.Residuals, "; "))))
		}
		if n := len(r.Gaps); n > 0 {
			lines = append(lines, fmt.Sprintf("*%d evidence gap%s to accept* (%s)", n, plural(n), Escape(strings.Join(r.Gaps, "; "))))
		}
		lines = append(lines, CopyAcceptInAuthSec)
		blocks = append(blocks, section(strings.Join(lines, "\n")))
	}
	blocks = append(blocks, noteInput("Reason (required to reject)", "Why this version should not be applied"))
	var elems []map[string]any
	if r.Approvable() {
		elems = append(elems, button(ActionApprove, "Approve", r.Value, "primary"))
		elems = append(elems, button(ActionReject, "Reject", r.Value, "danger"))
		if r.Link != "" {
			elems = append(elems, linkButton("Open in AuthSec", r.Link))
		}
	} else {
		if r.Link != "" {
			elems = append(elems, linkButton("Accept in AuthSec", r.Link))
		}
		elems = append(elems, button(ActionReject, "Reject", r.Value, "danger"))
	}
	blocks = append(blocks, actions("decision", elems...))
	return Message{Text: title, Blocks: blocks}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

/* ------------------------------- owner review ------------------------------ */

// OwnerReview is §9.3 S4 in Slack.
type OwnerReview struct {
	Title string   // "Review a change to RefundTaskRole"
	Lines []string // what changes
	Due   string   // "Fri 3 Oct 14:00 UTC"
	// Confirmations are the age and route items asked of this owner.
	Confirmations []LabeledValue
	// Removed are the services this owner may keep (retain).
	Removed []string
	Link    string
	Value   string
}

// BuildOwnerReview renders r: confirmations as checkboxes, a services
// picker, review date and note for Keep / This will break something, and
// the three responses (§7.4 acknowledge / retain / object).
func BuildOwnerReview(r OwnerReview) Message {
	blocks := []Block{header(r.Title)}
	if len(r.Lines) > 0 {
		var esc []string
		for _, l := range r.Lines {
			esc = append(esc, Escape(l))
		}
		blocks = append(blocks, section(strings.Join(esc, "\n")))
	}
	if r.Due != "" {
		blocks = append(blocks, contextLine("Due "+Escape(r.Due)+" · silence is not consent: the change waits for your answer"))
	}
	if len(r.Confirmations) > 0 {
		blocks = append(blocks, Block{"type": "input", "block_id": BlockConfirmations, "optional": true,
			"label":   text("Please confirm (required for Looks fine)"),
			"element": map[string]any{"type": "checkboxes", "action_id": "value", "options": options(r.Confirmations)}})
	}
	if len(r.Removed) > 0 {
		var opts []LabeledValue
		for _, s := range r.Removed {
			opts = append(opts, LabeledValue{Label: s, Value: s})
		}
		blocks = append(blocks, Block{"type": "input", "block_id": BlockRetainService, "optional": true,
			"label": text("Keep a service (for Keep a service…)"),
			"element": map[string]any{"type": "multi_static_select", "action_id": "value", "placeholder": text("Services to keep"),
				"options": options(opts)}})
		blocks = append(blocks, Block{"type": "input", "block_id": BlockReviewBy, "optional": true,
			"label":   text("Review the kept access by"),
			"element": map[string]any{"type": "datepicker", "action_id": "value", "placeholder": text("Review date")}})
	}
	blocks = append(blocks, noteInput("Reason or comment", "Why you keep a service, or what would break"))
	elems := []map[string]any{
		button(ActionAcknowledge, "Looks fine", r.Value, "primary"),
		button(ActionRetain, "Keep a service…", r.Value, ""),
		button(ActionObject, "This will break something…", r.Value, "danger"),
	}
	if r.Link != "" {
		elems = append(elems, linkButton("Open in AuthSec", r.Link))
	}
	blocks = append(blocks, actions("response", elems...))
	return Message{Text: r.Title, Blocks: blocks}
}

// ConfirmationValue is the checkbox value of an age ("a") or route ("r")
// confirmation: a short digest, because a route key can be longer than
// Slack's 150-character option value.
func ConfirmationValue(kind, service, route string) string {
	sum := sha256.Sum256([]byte(kind + "\x1f" + service + "\x1f" + route))
	return kind + ":" + hex.EncodeToString(sum[:])[:24]
}

/* ------------------------- deployment / canary notice ---------------------- */

// Notice is a deployment, canary or other notice.
type Notice struct {
	Title string
	Lines []string
	Link  string
	// Value set: the notice offers Report a problem / It's working (§9.3
	// S4 "during and after rollout").
	Value string
}

// BuildNotice renders n.
func BuildNotice(n Notice) Message {
	blocks := []Block{header(n.Title)}
	if len(n.Lines) > 0 {
		var esc []string
		for _, l := range n.Lines {
			esc = append(esc, Escape(l))
		}
		blocks = append(blocks, section(strings.Join(esc, "\n")))
	}
	var elems []map[string]any
	if n.Value != "" {
		blocks = append(blocks, noteInput("What you see", "What broke, or what you checked"))
		elems = append(elems, button(ActionReportProblem, "Report a problem", n.Value, "danger"),
			button(ActionWorking, "It's working", n.Value, "primary"))
	}
	if n.Link != "" {
		elems = append(elems, linkButton("Open in AuthSec", n.Link))
	}
	if len(elems) > 0 {
		blocks = append(blocks, actions("notice", elems...))
	}
	return Message{Text: n.Title, Blocks: blocks}
}

/* --------------------------------- outcomes -------------------------------- */

// Outcome replaces the clicked message with what happened ("Approved by
// Priya K. at 14:02").
func Outcome(title, line string) Message {
	blocks := []Block{section("*" + Escape(title) + "*")}
	if line != "" {
		blocks = append(blocks, contextLine(Escape(line)))
	}
	return Message{Text: title, Blocks: blocks, ReplaceOriginal: true}
}

// Refusal is an ephemeral answer to the clicking user only; link, when
// set, is offered as the next step.
func Refusal(copy, link, linkLabel string) Message {
	t := Escape(copy)
	if link != "" {
		if linkLabel == "" {
			linkLabel = "Open AuthSec"
		}
		t += "\n<" + link + "|" + Escape(linkLabel) + ">"
	}
	return Message{Text: copy, Blocks: []Block{section(t)}, ResponseType: "ephemeral"}
}

// HashDigest is the digest an approval button carries: sha256 over the
// sorted, newline-joined values (the intent, impact, plan and material
// hashes of the version as the message showed it).
func HashDigest(values ...[]string) string {
	var all []string
	for i, vs := range values {
		cp := append([]string{}, vs...)
		sort.Strings(cp)
		for _, v := range cp {
			all = append(all, fmt.Sprintf("%d:%s", i, v))
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(all, "\n")))
	return hex.EncodeToString(sum[:])[:32]
}
