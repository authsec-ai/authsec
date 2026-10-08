package slackapp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Slack's published example (api.slack.com/authentication/verifying-requests-from-slack).
const (
	docSecret = "8f742231b10e8888abcd99yyyzzz85a5"
	docTS     = "1531420618"
	docBody   = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c"
	docSig    = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
)

func hdr(sig, ts string) http.Header {
	h := http.Header{}
	if sig != "" {
		h.Set(HeaderSignature, sig)
	}
	if ts != "" {
		h.Set(HeaderTimestamp, ts)
	}
	return h
}

func reason(err error) string {
	if ve, ok := err.(*VerifyError); ok {
		return ve.Reason
	}
	if err == nil {
		return ""
	}
	return "other:" + err.Error()
}

func TestSignMatchesSlackExample(t *testing.T) {
	if got := Sign(docSecret, docTS, []byte(docBody)); got != docSig {
		t.Fatalf("Sign = %s, want %s", got, docSig)
	}
}

// Verify: the signature, the 5-minute window (both directions), missing
// and malformed headers, an unconfigured secret.
func TestVerify(t *testing.T) {
	sec, _ := strconv.ParseInt(docTS, 10, 64)
	at := time.Unix(sec, 0)
	body := []byte(docBody)
	cases := []struct {
		name   string
		secret string
		h      http.Header
		body   []byte
		now    time.Time
		want   string
	}{
		{"valid", docSecret, hdr(docSig, docTS), body, at.Add(time.Minute), ""},
		{"valid at the edge", docSecret, hdr(docSig, docTS), body, at.Add(MaxRequestAge), ""},
		{"stale by a second", docSecret, hdr(docSig, docTS), body, at.Add(MaxRequestAge + time.Second), ReasonStale},
		{"from the future", docSecret, hdr(docSig, docTS), body, at.Add(-MaxRequestAge - time.Second), ReasonStale},
		{"wrong secret", "another-secret", hdr(docSig, docTS), body, at, ReasonMismatch},
		{"body changed", docSecret, hdr(docSig, docTS), []byte(docBody + "&x=1"), at, ReasonMismatch},
		{"signature changed", docSecret, hdr(docSig[:len(docSig)-1]+"0", docTS), body, at, ReasonMismatch},
		{"v1 prefix", docSecret, hdr("v1"+docSig[2:], docTS), body, at, ReasonMismatch},
		{"no signature", docSecret, hdr("", docTS), body, at, ReasonMissing},
		{"no timestamp", docSecret, hdr(docSig, ""), body, at, ReasonMissing},
		{"bad timestamp", docSecret, hdr(docSig, "153142061x"), body, at, ReasonBadTimestamp},
		{"not configured", "", hdr(docSig, docTS), body, at, ReasonNotConfigured},
	}
	for _, tc := range cases {
		if got := reason(Verify(tc.secret, tc.h, tc.body, tc.now)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	// A timestamp re-signed with the right secret is valid again: the
	// window is on the signed timestamp, not on the body.
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	if err := Verify("s", hdr(Sign("s", ts, body), ts), body, now); err != nil {
		t.Fatal(err)
	}
}

func payloadBody(t *testing.T, v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(url.Values{"payload": {string(raw)}}.Encode())
}

func TestParseInteraction(t *testing.T) {
	val := ButtonValue{Notification: "8b0f9f4e-6a2f-4c1d-9f53-111111111111", Digest: "abc"}.Encode()
	body := payloadBody(t, map[string]any{
		"type": "block_actions", "team": map[string]any{"id": "T1"}, "user": map[string]any{"id": "U1", "team_id": "T1"},
		"container":    map[string]any{"type": "message", "message_ts": "1700000000.000001", "channel_id": "C1"},
		"response_url": "https://hooks.slack.com/actions/T1/1/x",
		"actions":      []any{map[string]any{"action_id": "approve", "value": val, "action_ts": "1700000001.123456"}},
		"state": map[string]any{"values": map[string]any{
			BlockNote:          map[string]any{"value": map[string]any{"type": "plain_text_input", "value": "  because  "}},
			BlockConfirmations: map[string]any{"value": map[string]any{"type": "checkboxes", "selected_options": []any{map[string]any{"value": "a:1"}, map[string]any{"value": "r:2"}}}},
			BlockReviewBy:      map[string]any{"value": map[string]any{"type": "datepicker", "selected_date": "2027-01-31"}},
		}},
	})
	in, err := ParseInteraction(body)
	if err != nil {
		t.Fatal(err)
	}
	if in.Type != TypeBlockActions || in.TeamID() != "T1" || in.User.ID != "U1" || in.MessageTS() != "1700000000.000001" ||
		len(in.Actions) != 1 || in.Actions[0].ActionTS != "1700000001.123456" {
		t.Fatalf("parsed %+v", in)
	}
	if in.Text(BlockNote) != "because" || in.Date(BlockReviewBy) != "2027-01-31" || strings.Join(in.Selected(BlockConfirmations), ",") != "a:1,r:2" {
		t.Fatalf("state: %q %q %v", in.Text(BlockNote), in.Date(BlockReviewBy), in.Selected(BlockConfirmations))
	}
	v, err := DecodeButtonValue(in.Actions[0].Value)
	if err != nil || v.Notification != "8b0f9f4e-6a2f-4c1d-9f53-111111111111" || v.Digest != "abc" {
		t.Fatalf("value %+v %v", v, err)
	}
	for _, bad := range [][]byte{nil, []byte("payload="), []byte("payload=%7Bnot-json"), []byte("x=1"), payloadBody(t, map[string]any{"user": "x"})} {
		if _, err := ParseInteraction(bad); err == nil {
			t.Errorf("ParseInteraction(%q) accepted", bad)
		}
	}
	if _, err := DecodeButtonValue("not base64!"); err == nil {
		t.Error("bad button value accepted")
	}
	for ts, ok := range map[string]bool{"1700000001.123456": true, "1700000001": false, "x.1": false, "1.2.3": false, "": false} {
		if ValidActionTS(ts) != ok {
			t.Errorf("ValidActionTS(%q) = %v", ts, !ok)
		}
	}
}

// actionIDs lists the action ids of every actions block of m.
func actionIDs(m Message) []string {
	var out []string
	for _, b := range m.Blocks {
		if b["type"] != "actions" {
			continue
		}
		for _, e := range b["elements"].([]any) {
			out = append(out, e.(map[string]any)["action_id"].(string))
		}
	}
	return out
}

// §9.3 S6: Approve only without residuals or gaps; with them, the
// message says acceptance happens in AuthSec.
func TestApprovalRequestButtons(t *testing.T) {
	base := ApprovalRequest{PolicyName: "Right-size RefundTaskRole", VersionNo: 2, Summary: []string{"Removes 1 AWS service from RefundTaskRole"},
		RequestedBy: "Asif A.", Link: "https://console.test/iga/policy/approvals", Value: "v"}
	m := BuildApprovalRequest(base)
	if got := strings.Join(actionIDs(m), ","); got != "approve,reject,open" {
		t.Fatalf("no residuals: %s", got)
	}
	r := base
	r.Residuals = []string{"sqs route through the queue policy of refunds"}
	m = BuildApprovalRequest(r)
	raw, _ := json.Marshal(m)
	if got := strings.Join(actionIDs(m), ","); got != "open,reject" || !strings.Contains(string(raw), "1 residual to accept") ||
		!strings.Contains(string(raw), "Accept in AuthSec") || !strings.Contains(string(raw), "cannot be approved from Slack") {
		t.Fatalf("residuals: %s\n%s", got, raw)
	}
	g := base
	g.Gaps = []string{"unanalysed_form:ecr_registry"}
	g.Link = ""
	if got := strings.Join(actionIDs(BuildApprovalRequest(g)), ","); got != "reject" {
		t.Fatalf("gaps, no link: %s", got)
	}
	// Mrkdwn control characters are escaped.
	e := base
	e.Summary = []string{"<!channel> & co"}
	sec := BuildApprovalRequest(e).Blocks[1]["text"].(map[string]any)["text"].(string)
	if strings.Contains(sec, "<!channel>") || !strings.Contains(sec, "&lt;!channel&gt; &amp; co") {
		t.Fatalf("not escaped: %s", sec)
	}
}

func TestOwnerReviewAndNoticeBlocks(t *testing.T) {
	m := BuildOwnerReview(OwnerReview{Title: "Review a change to RefundTaskRole", Lines: []string{"Removes sqs"}, Due: "Fri",
		Confirmations: []LabeledValue{{Label: "sqs was not added recently", Value: ConfirmationValue("a", "sqs", "")}},
		Removed:       []string{"sqs"}, Value: "v"})
	if got := strings.Join(actionIDs(m), ","); got != "acknowledge,retain,object" {
		t.Fatalf("owner review actions %s", got)
	}
	ids := map[string]bool{}
	for _, b := range m.Blocks {
		if id, ok := b["block_id"].(string); ok {
			ids[id] = true
		}
	}
	for _, want := range []string{BlockConfirmations, BlockRetainService, BlockReviewBy, BlockNote} {
		if !ids[want] {
			t.Errorf("owner review lacks block %s", want)
		}
	}
	if v := ConfirmationValue("r", "sqs", strings.Repeat("arn:aws:sqs:us-east-1:111111111111:q", 10)); len(v) > 150 {
		t.Fatalf("confirmation value %d chars", len(v))
	}
	if got := strings.Join(actionIDs(BuildNotice(Notice{Title: "Canary started", Value: "v"})), ","); got != "report_problem,working" {
		t.Fatalf("notice actions %s", got)
	}
	if got := actionIDs(BuildNotice(Notice{Title: "Drift"})); len(got) != 0 {
		t.Fatalf("plain notice actions %v", got)
	}
	if HashDigest([]string{"a"}, []string{"b", "c"}) != HashDigest([]string{"a"}, []string{"c", "b"}) ||
		HashDigest([]string{"a"}, []string{"b"}) == HashDigest([]string{"b"}, []string{"a"}) {
		t.Fatal("HashDigest must sort within a list and keep lists apart")
	}
}

// HTTPAPI against a fake Slack: methods, bearer token, ok:false errors,
// the response_url host pin.
func TestHTTPAPI(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/oauth.v2.access":
			_, _ = w.Write([]byte(`{"ok":true,"access_token":"xoxb-1","bot_user_id":"B1","scope":"chat:write","team":{"id":"T1","name":"Acme"}}`))
		case "/api/chat.postMessage":
			_, _ = w.Write([]byte(`{"ok":true,"ts":"1700000000.000100","channel":"C1"}`))
		case "/api/users.lookupByEmail":
			_, _ = w.Write([]byte(`{"ok":false,"error":"users_not_found"}`))
		case "/api/users.info":
			_, _ = w.Write([]byte(`{"ok":true,"user":{"id":"U1","team_id":"T1","is_email_confirmed":true,"profile":{"email":"a@x.test"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	api := &HTTPAPI{Client: srv.Client(), BaseURL: srv.URL + "/api"}
	ctx := context.Background()
	res, err := api.OAuthV2Access(ctx, "cid", "csecret", "code", "https://cb")
	if err != nil || res.AccessToken != "xoxb-1" || res.TeamID != "T1" || res.TeamName != "Acme" {
		t.Fatalf("oauth %+v %v", res, err)
	}
	ts, ch, err := api.PostMessage(ctx, "xoxb-1", "C1", Message{Text: "hi"})
	if err != nil || ts != "1700000000.000100" || ch != "C1" || !strings.Contains(seen[1], "Bearer xoxb-1") {
		t.Fatalf("post %s %s %v %v", ts, ch, err, seen)
	}
	if _, err := api.LookupByEmail(ctx, "xoxb-1", "a@x.test"); !IsAPIError(err, "users_not_found") {
		t.Fatalf("lookup: %v", err)
	}
	u, err := api.UsersInfo(ctx, "xoxb-1", "U1")
	if err != nil || u.Email != "a@x.test" || !u.IsEmailConfirmed {
		t.Fatalf("users.info %+v %v", u, err)
	}
	for u, ok := range map[string]bool{"https://hooks.slack.com/actions/T/1/x": true, "http://hooks.slack.com/x": false,
		"https://evil.test/x": false, "https://hooks.slack.com.evil.test/x": false, "https://u:p@hooks.slack.com/x": false} {
		if ValidResponseURL(u, nil) != ok {
			t.Errorf("ValidResponseURL(%s) = %v", u, !ok)
		}
	}
	if err := api.Respond(ctx, srv.URL+"/x", Message{}); err == nil {
		t.Fatal("response_url to a non-Slack host was posted")
	}
}
